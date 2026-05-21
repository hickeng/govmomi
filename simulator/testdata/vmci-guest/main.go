// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// vmci-guest is the single static linux/amd64 test binary for all vcsim
// VMCI/vsock interception tests.  It is injected into container-backed VMs via
// RUN.volume at container start (same mechanism as vsock-test) and exec'd via
// "docker exec" to exercise individual paths.  Each exec spawns a new process
// tree, causing crun to open a new seccompFd connection to the vcsim listener
// and exercising the Phase 6a multi-accept path.
//
// Subcommands:
//
//	grpc-set KEY VALUE
//	    Connect via AF_VSOCK to port 976 (GuestRPC), send an info-set command,
//	    and verify the ACK.  Exit 0 on success.
//
//	grpc-get KEY
//	    Connect via AF_VSOCK to port 976 (GuestRPC), send an info-get command,
//	    and print the bare value (no "1 " prefix) to stdout.  Exit 0 on success.
//
//	grpc-roundtrip KEY VALUE
//	    Connect via AF_VSOCK to port 976, set KEY=VALUE, then get KEY and verify
//	    the round-trip.  Exits 0 on success.  Replaces vsock-test-intercept.
//
//	rpc-cmd COMMAND
//	    Send COMMAND (a single string, e.g. "info-get guestinfo.KEY") to the
//	    GuestRPC server via AF_VSOCK port 976.  On success prints the bare value
//	    (without the "1 " prefix) to stdout and exits 0; exits 1 on failure.
//	    Also invoked implicitly when the binary is named "vmware-rpctool" so
//	    it can act as a drop-in replacement for the system vmware-rpctool.
//
//	bidi PORT WANT_FROM_HOST SEND_TO_HOST
//	    Connect via AF_VSOCK to PORT.  Read a newline-terminated message from
//	    the host and verify it equals WANT_FROM_HOST.  Send SEND_TO_HOST
//	    (newline-terminated) to the host.  Exit 0 on success.
//	    Exercises bidirectional data flow: host→guest and guest→host.
//
// Build:
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
//	  -o /tmp/vmci-guest \
//	  github.com/vmware/govmomi/simulator/testdata/vmci-guest
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	afVsock       = 40  // AF_VSOCK
	vmaddrCIDHost = 2   // VMADDR_CID_HOST — the hypervisor CID
	rpciPort      = 976 // VMware RPCI/GuestRPC vsock port
	maxFrameBytes = 1 << 20
)

// sockaddrVM mirrors struct sockaddr_vm from <linux/vm_sockets.h> (amd64 layout).
//
//	uint16 svm_family
//	uint16 svm_reserved1
//	uint32 svm_port
//	uint32 svm_cid
//	uint8  svm_flags
//	uint8  svm_zero[3]
type sockaddrVM struct {
	family    uint16
	reserved1 uint16
	port      uint32
	cid       uint32
	flags     uint8
	pad       [3]uint8
}

// vsockDial opens an AF_VSOCK stream socket and connects it to cid:port.
// Returns an *os.File that wraps the raw FD; caller must Close it.
//
// Both syscalls (socket and connect) are issued as raw syscalls so the vcsim
// seccomp filter can intercept and replace the FD with a unix socketpair.
func vsockDial(cid, port uint32) (*os.File, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}

	addr := sockaddrVM{
		family: afVsock,
		port:   port,
		cid:    cid,
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("connect(cid=%d, port=%d): %w", cid, port, errno)
	}
	return os.NewFile(uintptr(fd), fmt.Sprintf("vsock-cid%d-port%d", cid, port)), nil
}

// writeFrame writes a 4-byte LE length-prefixed payload — the GuestRPC wire format.
func writeFrame(w io.Writer, payload string) error {
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := io.WriteString(w, payload)
	return err
}

// readFrame reads a 4-byte LE length-prefixed payload.
func readFrame(r io.Reader) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", fmt.Errorf("read header: %w", err)
	}
	n := binary.LittleEndian.Uint32(hdr)
	if n == 0 {
		return "", nil
	}
	if n > maxFrameBytes {
		return "", fmt.Errorf("frame too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	return string(buf), nil
}

// guestRPCRoundTrip sends cmd via GuestRPC framing on the given file and
// returns the raw response string (including the "1 " prefix on success).
func guestRPCRoundTrip(f *os.File, cmd string) (string, error) {
	if err := writeFrame(f, cmd); err != nil {
		return "", fmt.Errorf("writeFrame(%q): %w", cmd, err)
	}
	resp, err := readFrame(f)
	if err != nil {
		return "", fmt.Errorf("readFrame: %w", err)
	}
	return resp, nil
}

// cmdGRPCSet connects to GuestRPC port and issues info-set KEY VALUE.
func cmdGRPCSet(key, value string) error {
	f, err := vsockDial(vmaddrCIDHost, rpciPort)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := guestRPCRoundTrip(f, "info-set "+key+" "+value)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "1 ") {
		return fmt.Errorf("info-set: unexpected response %q", resp)
	}
	return nil
}

// cmdGRPCRoundTrip connects to GuestRPC port, sets KEY=VALUE, then gets KEY
// and verifies the returned value matches.  Intended as a simple smoke-test
// that the full intercept chain works end-to-end.
func cmdGRPCRoundTrip(key, value string) error {
	f, err := vsockDial(vmaddrCIDHost, rpciPort)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := guestRPCRoundTrip(f, "info-set "+key+" "+value)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "1 ") {
		return fmt.Errorf("info-set: unexpected response %q", resp)
	}

	resp, err = guestRPCRoundTrip(f, "info-get "+key)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "1 ") {
		return fmt.Errorf("info-get: unexpected response %q", resp)
	}
	got := strings.TrimPrefix(resp, "1 ")
	if got != value {
		return fmt.Errorf("roundtrip mismatch: got %q, want %q", got, value)
	}
	fmt.Printf("roundtrip OK: %s=%s\n", key, got)
	return nil
}

// cmdGRPCGet connects to GuestRPC port and issues info-get KEY.
// Prints the bare value (without the "1 " prefix) to stdout.
func cmdGRPCGet(key string) error {
	f, err := vsockDial(vmaddrCIDHost, rpciPort)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := guestRPCRoundTrip(f, "info-get "+key)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(resp, "1 ") {
		return fmt.Errorf("info-get: unexpected response %q", resp)
	}
	fmt.Println(strings.TrimPrefix(resp, "1 "))
	return nil
}

// cmdRPCCmd sends a raw GuestRPC command string and prints the raw server
// response, matching the real vmware-rpctool wire contract:
//
//	Exit 0 + print "1 VALUE"          when the server responds "1 VALUE" (found)
//	Exit 0 + print "0 No value found" when the server responds "0 ..." (missing key)
//	Exit 1 (no output)                on channel failure (connect error, I/O error)
//
// This exit-code semantics is CRITICAL for cloud-init's DataSourceVMware:
//   - Exit 0 → VMware environment detected (datasource selects DataSourceVMware)
//   - Exit 1 → channel failure → datasource falls back to None
//
// The real vmware-rpctool binary prints the raw "1 …" / "0 …" response and
// exits 0 for any successful channel round-trip (including "key not found").
// cloud-init parses the "1 " prefix itself to distinguish found vs. missing.
//
// This allows the binary to replace the system vmware-rpctool (which may be
// statically linked, bypassing LD_PRELOAD shims) while preserving full
// cloud-init compatibility.
func cmdRPCCmd(command string) error {
	f, err := vsockDial(vmaddrCIDHost, rpciPort)
	if err != nil {
		// Channel failure: exit 1, no output — cloud-init will not identify VMware.
		return err
	}
	defer f.Close()

	resp, err := guestRPCRoundTrip(f, command)
	if err != nil {
		return err
	}
	// Print the raw response including the "1 " or "0 " prefix.  Cloud-init
	// parses this itself to distinguish found vs. missing keys.
	fmt.Println(resp)
	return nil // always exit 0 for successful channel round-trips
}

// cmdBidi connects to port via AF_VSOCK and performs a bidirectional exchange:
//  1. Reads a newline-terminated message from the host; verifies == wantFromHost.
//  2. Sends sendToHost (newline-terminated) to the host.
//
// Exits 0 on success.  This exercises:
//   - Host→Guest direction (host sends first, guest reads).
//   - Guest→Host direction (guest sends, host reads).
func cmdBidi(port uint32, wantFromHost, sendToHost string) error {
	f, err := vsockDial(vmaddrCIDHost, port)
	if err != nil {
		return err
	}
	defer f.Close()

	// Host→Guest: read host's message (newline-terminated).
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read from host: %w", err)
		}
		return fmt.Errorf("read from host: unexpected EOF")
	}
	got := scanner.Text()
	if got != wantFromHost {
		return fmt.Errorf("host message: got %q, want %q", got, wantFromHost)
	}

	// Guest→Host: send our message (newline-terminated).
	if _, err := fmt.Fprintln(f, sendToHost); err != nil {
		return fmt.Errorf("write to host: %w", err)
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `vmci-guest — vcsim VMCI/vsock test agent

Subcommands:
  grpc-set KEY VALUE
      Set KEY to VALUE via AF_VSOCK GuestRPC (port 976).

  grpc-get KEY
      Print the value of KEY via AF_VSOCK GuestRPC (port 976).

  grpc-roundtrip KEY VALUE
      Set KEY=VALUE and get it back, verifying the round-trip.

  rpc-cmd COMMAND
      Send COMMAND (e.g. "info-get guestinfo.KEY") to the GuestRPC server.
      Prints the value on success; exits 1 on failure.

  bidi PORT WANT_FROM_HOST SEND_TO_HOST
      Connect to PORT, read WANT_FROM_HOST from host, send SEND_TO_HOST.
      Tests bidirectional communication through a custom port handler.`)
	os.Exit(2)
}

func main() {
	// vmware-rpctool compatibility mode: when the binary is installed under a
	// name that contains "vmware-rpctool", treat the first argument as a raw
	// GuestRPC command string (e.g. 'info-get guestinfo.metadata') and forward
	// it to the GuestRPC server via AF_VSOCK.  This allows the binary to replace
	// the system vmware-rpctool — which may be statically linked and therefore
	// immune to LD_PRELOAD shims — without modifying the container image.
	if strings.Contains(filepath.Base(os.Args[0]), "vmware-rpctool") {
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: vmware-rpctool 'COMMAND'")
			os.Exit(2)
		}
		if err := cmdRPCCmd(os.Args[1]); err != nil {
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		usage()
	}

	var err error
	switch os.Args[1] {
	case "grpc-set":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: vmci-guest grpc-set KEY VALUE")
			os.Exit(2)
		}
		err = cmdGRPCSet(os.Args[2], os.Args[3])

	case "grpc-get":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: vmci-guest grpc-get KEY")
			os.Exit(2)
		}
		err = cmdGRPCGet(os.Args[2])

	case "grpc-roundtrip":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: vmci-guest grpc-roundtrip KEY VALUE")
			os.Exit(2)
		}
		err = cmdGRPCRoundTrip(os.Args[2], os.Args[3])

	case "rpc-cmd":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: vmci-guest rpc-cmd 'COMMAND'")
			os.Exit(2)
		}
		err = cmdRPCCmd(os.Args[2])

	case "bidi":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: vmci-guest bidi PORT WANT_FROM_HOST SEND_TO_HOST")
			os.Exit(2)
		}
		p, parseErr := strconv.ParseUint(os.Args[2], 10, 32)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "invalid port %q: %v\n", os.Args[2], parseErr)
			os.Exit(2)
		}
		err = cmdBidi(uint32(p), os.Args[3], os.Args[4])

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
