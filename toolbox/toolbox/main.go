// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

// toolbox is the govmomi guest-side agent binary.
//
// It implements the VMware GuestRPC RPCI protocol and can be used both on real
// ESX/Fusion/Workstation VMs (via the x86 backdoor channel) and inside
// govmomi/simulator container-backed VMs (via AF_VSOCK + DataMap framing, where
// the seccomp-based intercept transparently replaces the vsock FD with a Unix
// socketpair connected to the GuestRPCServer).
//
// Transport selection:
//
//	AF_VSOCK (DataMap) is tried first.  This works on:
//	  • Real ESX VMs with the vmci kernel module loaded.
//	  • govmomi/simulator container-backed VMs with RUN.vmci=true.
//	If AF_VSOCK is unavailable, the binary falls back to the x86 backdoor (for
//	real VM environments running on VMware hypervisors).
//
// # Invocation modes
//
// Daemon mode (no --cmd):
//
//	toolbox            — register capabilities + poll TCLO (vsock) / backdoor
//
// One-shot RPCI mode:
//
//	toolbox --cmd "info-get guestinfo.KEY"
//	toolbox --cmd "info-set guestinfo.KEY VALUE"
//	toolbox --cmd "RPCI_COMMAND"
//
//	In vmtoolsd --cmd semantics:
//	  • info-get: print bare value to stdout; exit 0 on found, exit 1 on missing.
//	  • info-set: exit 0 on success, exit 1 on failure.
//	  • capability / state RPCs: exit 0 immediately (no server round-trip needed).
//	  • other RPCs: exit 0 on "1 ..." response, exit 1 on "0 ..." response.
//
// vmware-rpctool compatibility (invoked as "vmware-rpctool"):
//
//	vmware-rpctool 'RPCI_COMMAND'
//
//	Sends the raw command, prints the raw "1 VALUE" or "0 reason" response, and
//	exits 0 on a successful channel round-trip (including "0 No value found").
//	Exits 1 only on channel failure.  This matches the real vmware-rpctool
//	contract that cloud-init DataSourceVMware relies on.
//
// # Container injection
//
// Build a static linux/amd64 binary and volume-overlay it into the container:
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
//	  -o /tmp/toolbox \
//	  github.com/vmware/govmomi/toolbox/toolbox
//
// Then in ExtraConfig:
//
//	"RUN.volume.vmtoolsd":     "/tmp/toolbox:/usr/bin/vmtoolsd:ro",
//	"RUN.volume.vmware-rpc":   "/tmp/toolbox:/usr/bin/vmware-rpctool:ro",
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vmware/govmomi/toolbox"
)

func main() {
	// vmware-rpctool compatibility: when invoked as "vmware-rpctool", treat
	// the single positional argument as a raw GuestRPC command string.
	if strings.Contains(filepath.Base(os.Args[0]), "vmware-rpctool") {
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: vmware-rpctool 'COMMAND'")
			os.Exit(2)
		}
		if err := rpcCmd(os.Args[1]); err != nil {
			os.Exit(1)
		}
		return
	}

	cmdArg := flag.String("cmd", "", "send a one-shot RPCI command and exit (vmtoolsd --cmd semantics)")
	flag.Parse()

	if *cmdArg != "" {
		if err := vmtoolsdCmd(*cmdArg); err != nil {
			os.Exit(1)
		}
		return
	}

	// Daemon mode: start the full toolbox service.
	in, out := selectChannels()
	service := toolbox.NewService(in, out)

	if os.Getuid() == 0 {
		service.Power.Halt.Handler = toolbox.Halt
		service.Power.Reboot.Handler = toolbox.Reboot
	}

	if err := service.Start(); err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Printf("signal %s received", <-sig)
		service.Stop()
	}()

	service.Wait()
}

// selectChannels returns (in, out) channels for the daemon mode.
//
// Preference: AF_VSOCK (VsockChannel + NoopChannelIn) for both simulated and
// real ESX environments. toolbox.IsVsockAvailable() probes socket(AF_VSOCK)
// without opening a connection; it returns true on:
//   - Real ESX VMs with the vmci kernel module loaded.
//   - govmomi/simulator container-backed VMs with RUN.vmci=true (seccomp intercept).
//
// On non-Linux, bare containers, or non-VM hosts, IsVsockAvailable returns false
// and the backdoor fallback is used.
func selectChannels() (toolbox.Channel, toolbox.Channel) {
	if toolbox.IsVsockAvailable() {
		return toolbox.NewNoopChannelIn(), toolbox.NewVsockChannelOut()
	}
	// Fallback: traditional VMware x86 backdoor (real VM on ESX/Fusion/Workstation).
	return toolbox.NewBackdoorChannelIn(), toolbox.NewBackdoorChannelOut()
}

// rpcCmd sends a raw GuestRPC command and prints the raw server response
// ("1 VALUE" or "0 reason") to stdout, then exits.
//
// Exit semantics match the real vmware-rpctool binary:
//   - Exit 0 + print response on a successful channel round-trip.
//   - Exit 1 (no output) on channel failure (connect error, I/O error).
//
// cloud-init DataSourceVMware calls vmware-rpctool and checks:
//   - "1 " prefix → VMware environment, datasource active.
//   - "0 " prefix or exit 1 → not VMware / key missing, datasource deactivates.
func rpcCmd(command string) error {
	out := toolbox.NewVsockChannelOut()
	if err := out.Start(); err != nil {
		return err
	}
	if err := out.Send([]byte(command)); err != nil {
		return err
	}
	reply, err := out.Receive()
	if err != nil {
		return err
	}
	fmt.Println(string(reply))
	return nil
}

// vmtoolsdCmd dispatches a vmtoolsd --cmd "COMMAND" argument.
//
// Exit semantics match the real vmtoolsd binary:
//   - info-get KEY: print bare value, exit 0 (found) or exit 1 (missing/error).
//   - info-set KEY VAL: exit 0 on success, exit 1 on failure.
//   - tools.* / Capabilities_Register / Set_Option: acknowledge, exit 0.
//   - other RPCs: exit 0 on "1 ..." response, exit 1 on "0 ..." response.
func vmtoolsdCmd(command string) error {
	command = strings.TrimSpace(command)

	// Capability and state RPCs do not require a server round-trip.
	if strings.HasPrefix(command, "tools.") ||
		strings.HasPrefix(command, "Capabilities_Register") ||
		strings.HasPrefix(command, "Set_Option ") {
		return nil
	}

	out := toolbox.NewVsockChannelOut()
	if err := out.Start(); err != nil {
		return err
	}
	ch := &toolbox.ChannelOut{Channel: out}

	if strings.HasPrefix(command, "info-get ") {
		// info-get: exit 0 + print bare value on success; exit 1 on missing.
		// ChannelOut.Request strips the "1 " prefix on success and returns
		// an error (wrapping the "0 ..." response) on failure.
		val, err := ch.Request([]byte(command))
		if err != nil {
			return err
		}
		// Strip the trailing null byte that some callers append.
		fmt.Println(string(bytes.TrimRight(val, "\x00")))
		return nil
	}

	// info-set and everything else: success = "1 ...", failure = "0 ...".
	_, err := ch.Request([]byte(command))
	return err
}
