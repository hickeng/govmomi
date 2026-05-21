// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

// toolbox is a GuestRPC agent binary built on the govmomi/toolbox library.
//
// It is intended to be embedded in guest processes (custom init processes,
// container-backed VMs, test harnesses) that need VMware GuestRPC / guestinfo
// functionality without linking to the full open-vm-tools stack.
//
// # Transport selection
//
// All modes (daemon, one-shot, rpctool) share the same selection logic:
//
//	1. AF_VSOCK with DataMap framing is tried first.  Works on:
//	   • Real ESX VMs with the vmci kernel module loaded.
//	   • govmomi/simulator container-backed VMs (RUN.vmci=true via seccomp
//	     intercept that replaces the vsock FD with a Unix socketpair).
//	2. x86 backdoor channel (in eax,dx / port 0x5658) is used as fallback
//	   when AF_VSOCK is unavailable (VMware Workstation/Fusion, or ESX VMs
//	   without the vmci kernel module).
//
// Errors from channel open are always reported to stderr; the binary never
// fails silently.
//
// # Invocation modes
//
// Daemon mode (no --cmd):
//
//	toolbox            — register capabilities + poll TCLO (vsock or backdoor)
//
// One-shot RPCI mode (vmtoolsd --cmd semantics):
//
//	toolbox --cmd "info-get guestinfo.KEY"
//	toolbox --cmd "info-set guestinfo.KEY VALUE"
//	toolbox --cmd "RPCI_COMMAND"
//
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
			fmt.Fprintf(os.Stderr, "vmware-rpctool: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cmdArg := flag.String("cmd", "", "send a one-shot RPCI command and exit (vmtoolsd --cmd semantics)")
	flag.Parse()

	if *cmdArg != "" {
		if err := vmtoolsdCmd(*cmdArg); err != nil {
			fmt.Fprintf(os.Stderr, "vmtoolsd: %v\n", err)
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

// selectChannels returns (in, out) channels for daemon mode using the same
// preference order as openRPCChannel: AF_VSOCK first, backdoor as fallback.
func selectChannels() (toolbox.Channel, toolbox.Channel) {
	if toolbox.IsVsockAvailable() {
		return toolbox.NewNoopChannelIn(), toolbox.NewVsockChannelOut()
	}
	return toolbox.NewBackdoorChannelIn(), toolbox.NewBackdoorChannelOut()
}

// openRPCChannel returns the best available GuestRPC outbound channel.
//
// Selection order:
//  1. AF_VSOCK (DataMap framing) — works on real ESX VMs with the vmci kernel
//     module and on govmomi/simulator container-backed VMs (RUN.vmci=true).
//  2. x86 backdoor — works on VMware Workstation/Fusion and ESX VMs without
//     the vmci module.
//
// Returns a non-nil error (with a descriptive message) if neither transport
// can be opened; the binary never fails silently.
func openRPCChannel() (toolbox.Channel, error) {
	if toolbox.IsVsockAvailable() {
		ch := toolbox.NewVsockChannelOut()
		if err := ch.Start(); err == nil {
			return ch, nil
		}
	}
	ch := toolbox.NewBackdoorChannelOut()
	if err := ch.Start(); err != nil {
		return nil, fmt.Errorf("GuestRPC channel unavailable: AF_VSOCK not present and backdoor failed: %w", err)
	}
	return ch, nil
}

// rpcCmd sends a raw GuestRPC command and prints the raw server response
// ("1 VALUE" or "0 reason") to stdout, then exits.
//
// Exit semantics match the real vmware-rpctool binary:
//   - Exit 0 + print response on a successful channel round-trip.
//   - Exit 1 + message on stderr on channel failure (connect error, I/O error).
//
// cloud-init DataSourceVMware calls vmware-rpctool and checks:
//   - "1 " prefix → VMware environment, datasource active.
//   - "0 " prefix or exit 1 → not VMware / key missing, datasource deactivates.
func rpcCmd(command string) error {
	ch, err := openRPCChannel()
	if err != nil {
		return err
	}
	defer ch.Stop()

	if err := ch.Send([]byte(command)); err != nil {
		return err
	}
	reply, err := ch.Receive()
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
//   - channel failure: exit 1 + message on stderr.
func vmtoolsdCmd(command string) error {
	command = strings.TrimSpace(command)

	// Capability and state RPCs are acknowledged without a server round-trip.
	// The real vmtoolsd also short-circuits these in some configurations.
	if strings.HasPrefix(command, "tools.") ||
		strings.HasPrefix(command, "Capabilities_Register") ||
		strings.HasPrefix(command, "Set_Option ") {
		return nil
	}

	ch, err := openRPCChannel()
	if err != nil {
		return err
	}
	defer ch.Stop()
	rpci := &toolbox.ChannelOut{Channel: ch}

	if strings.HasPrefix(command, "info-get ") {
		// info-get: exit 0 + print bare value on success; exit 1 on missing.
		// ChannelOut.Request strips the "1 " prefix on success and returns
		// an error (wrapping the "0 ..." response) on failure.
		val, err := rpci.Request([]byte(command))
		if err != nil {
			return err
		}
		// Strip the trailing null byte that some callers append.
		fmt.Println(string(bytes.TrimRight(val, "\x00")))
		return nil
	}

	// info-set and everything else: success = "1 ...", failure = "0 ...".
	_, err = rpci.Request([]byte(command))
	return err
}
