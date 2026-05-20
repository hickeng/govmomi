// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package simulator

// Container-free tests for the VMCI port registry and multi-connection paths.
//
// These tests exercise:
//   - vmciPortRegistry: register, lookup, setDefault, overwrite, concurrency
//   - VMCIPortHandler: argument passing, bidirectional I/O
//   - Multiple concurrent connections to the same GuestRPC port (multi-client)
//   - Multiple concurrent connections to different ports (port routing)
//   - vsockIntercept.Stop: seccompFd cleanup and WaitGroup completion
//
// No containers, no seccomp machinery — all tests use unix socketpairs to
// simulate the guest-end FD that the seccomp handler would inject into the
// container, exactly as handleSocket does in production.

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vmware/govmomi/toolbox"
)

// ── vmciPortRegistry unit tests ───────────────────────────────────────────────

// TestVMCI_Registry_Lookup verifies basic register + lookup semantics.
func TestVMCI_Registry_Lookup(t *testing.T) {
	r := newVMCIPortRegistry()

	// Empty registry returns nil.
	require.Nil(t, r.lookup(976), "empty registry must return nil for any port")

	var called bool
	r.register(976, func(_ string, _ int, _, _ uint32) { called = true })

	h := r.lookup(976)
	require.NotNil(t, h, "lookup after register must return the handler")
	h("", -1, 0, 976)
	require.True(t, called, "looked-up handler must be callable")
}

// TestVMCI_Registry_Default verifies that setDefault provides a fallback for
// unregistered ports without shadowing port-specific registrations.
func TestVMCI_Registry_Default(t *testing.T) {
	r := newVMCIPortRegistry()

	// Before setDefault, unregistered port returns nil.
	require.Nil(t, r.lookup(12345), "lookup must return nil before setDefault")

	var defaultCalled bool
	r.setDefault(func(_ string, _ int, _, _ uint32) { defaultCalled = true })

	h := r.lookup(12345)
	require.NotNil(t, h, "lookup for unregistered port must return default handler")
	h("", -1, 0, 12345)
	require.True(t, defaultCalled, "default handler must be callable")

	// A port-specific registration still wins over the default.
	var p976Called bool
	r.register(976, func(_ string, _ int, _, _ uint32) { p976Called = true })
	r.lookup(976)("", -1, 0, 976)
	require.True(t, p976Called, "port-specific handler must win over default")

	// Default is still returned for other unregistered ports.
	require.NotNil(t, r.lookup(8080), "default must still cover other unregistered ports")
}

// TestVMCI_Registry_Overwrite verifies that re-registering a port atomically
// replaces the previous handler.
func TestVMCI_Registry_Overwrite(t *testing.T) {
	r := newVMCIPortRegistry()

	var first, second bool
	r.register(1234, func(_ string, _ int, _, _ uint32) { first = true })
	r.register(1234, func(_ string, _ int, _, _ uint32) { second = true })

	r.lookup(1234)("", -1, 0, 1234)
	require.False(t, first, "first handler must have been replaced by second register")
	require.True(t, second, "second handler must be active after overwrite")
}

// TestVMCI_Registry_Concurrency verifies that concurrent register+lookup calls
// do not race.  Run with -race to detect data races.
func TestVMCI_Registry_Concurrency(t *testing.T) {
	r := newVMCIPortRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		port := uint32(i % 5) // 5 distinct ports, 4 goroutines per port
		go func(p uint32) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.register(p, func(_ string, _ int, _, _ uint32) {})
				_ = r.lookup(p)
			}
		}(port)
	}
	wg.Wait()
}

// ── VMCIPortHandler argument-passing tests ────────────────────────────────────

// TestVMCI_HandlerArguments verifies that the handler receives the exact vmUID,
// hostFd, cid, and port values passed by the dispatch caller.
func TestVMCI_HandlerArguments(t *testing.T) {
	vi := &vsockIntercept{
		vmUID: "vm-args-test",
		reg:   newVMCIPortRegistry(),
	}

	type callArgs struct {
		uid  string
		fd   int
		cid  uint32
		port uint32
	}
	got := make(chan callArgs, 1)

	vi.reg.register(5678, func(vmUID string, hostFd int, cid, port uint32) {
		got <- callArgs{uid: vmUID, fd: hostFd, cid: cid, port: port}
	})

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { syscall.Close(fds[1]) }) // guest end; handler owns fds[0]

	h := vi.reg.lookup(5678)
	require.NotNil(t, h)
	go h(vi.vmUID, fds[0], 3 /* VMADDR_CID_HOST */, 5678)

	select {
	case a := <-got:
		require.Equal(t, "vm-args-test", a.uid)
		require.Equal(t, uint32(3), a.cid)
		require.Equal(t, uint32(5678), a.port)
		require.Greater(t, a.fd, 0, "hostFd must be a valid open descriptor")
	case <-time.After(2 * time.Second):
		t.Fatal("handler not called within timeout")
	}
}

// ── Bidirectional I/O test ────────────────────────────────────────────────────

// TestVMCI_HandlerBidirectional verifies that a VMCIPortHandler can both
// receive data from the container (VM→Host) and send data back (Host→VM) using
// the same socketpair.
//
// Design note: once the seccomp intercept has injected a unix socketpair, the
// established channel is fully bidirectional — the host end (hostFd, owned by
// the handler) can write to the container regardless of which side "initiated".
// This models what a real DialVM implementation would expose for host-initiated
// connections once bidirectional flows are needed (FU-97-07).
func TestVMCI_HandlerBidirectional(t *testing.T) {
	const testPort = uint32(9999)
	const containerMsg = "ping from container"
	const hostReply = "pong from host"

	vi := &vsockIntercept{
		vmUID: "vm-bidi-test",
		reg:   newVMCIPortRegistry(),
	}

	handlerDone := make(chan error, 1)

	// Handler: reads containerMsg, writes hostReply (Host→VM direction).
	vi.reg.register(testPort, func(vmUID string, hostFd int, cid, port uint32) {
		f := os.NewFile(uintptr(hostFd), "vmci-host")
		hostConn, err := net.FileConn(f)
		f.Close() // net.FileConn dups the fd; original is released here
		if err != nil {
			handlerDone <- fmt.Errorf("FileConn: %w", err)
			return
		}
		defer hostConn.Close()

		buf := make([]byte, len(containerMsg))
		if _, err := io.ReadFull(hostConn, buf); err != nil {
			handlerDone <- fmt.Errorf("ReadFull from container: %w", err)
			return
		}
		if string(buf) != containerMsg {
			handlerDone <- fmt.Errorf("got %q want %q", buf, containerMsg)
			return
		}

		if _, err := hostConn.Write([]byte(hostReply)); err != nil {
			handlerDone <- fmt.Errorf("Write reply to container: %w", err)
			return
		}
		handlerDone <- nil
	})

	// Simulate the container: create socketpair, wrap the guest end.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)

	f := os.NewFile(uintptr(fds[1]), "vmci-guest")
	guestConn, err := net.FileConn(f)
	f.Close()
	require.NoError(t, err)
	defer guestConn.Close()

	h := vi.reg.lookup(testPort)
	require.NotNil(t, h)
	go h(vi.vmUID, fds[0], 2 /* VMADDR_CID_HYPERVISOR */, testPort)

	// Container sends data (VM→Host direction).
	_, err = guestConn.Write([]byte(containerMsg))
	require.NoError(t, err, "container write to host")

	// Container reads the host's reply (Host→VM direction).
	reply := make([]byte, len(hostReply))
	_, err = io.ReadFull(guestConn, reply)
	require.NoError(t, err, "container read host reply")
	require.Equal(t, hostReply, string(reply), "host reply must reach container")

	select {
	case handlerErr := <-handlerDone:
		require.NoError(t, handlerErr, "handler must exit cleanly")
	case <-time.After(5 * time.Second):
		t.Fatal("handler goroutine did not exit after bidirectional exchange")
	}
}

// ── Multi-connection tests ─────────────────────────────────────────────────────

// TestVMCI_MultipleConnections_SamePort runs N concurrent GuestRPC bridge
// connections to a single VM's GuestRPC server, each doing an independent
// info-set / info-get round-trip.
//
// This simulates N concurrent vmtoolsd instances, N podman exec invocations
// each running vmware-rpctool, or any other scenario where multiple in-container
// processes connect to the same VMCI port concurrently.
func TestVMCI_MultipleConnections_SamePort(t *testing.T) {
	
	const n = 5

	env := newVCSIMEnv(t)
	vmObj := firstVM(env.simCtx)
	require.NotNil(t, vmObj)

	_, vi := newTestBridge(t, "-mcsp", vmObj, env.simCtx)

	// Pre-create all socket pairs in the test goroutine so that require calls
	// (which call t.FailNow → runtime.Goexit) are issued from the correct goroutine.
	type connPair struct {
		hostFd    int
		guestConn net.Conn
	}
	pairs := make([]connPair, n)
	for i := range pairs {
		pairs[i].hostFd, pairs[i].guestConn = socketpairConn(t)
	}

	type result struct {
		setResp string
		getResp string
		err     error
	}
	results := make([]result, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()

			pair := pairs[i]
			bridgeDone := runBridge(vi, pair.hostFd)

			key := fmt.Sprintf("guestinfo.mcsp.key%d", i)
			val := fmt.Sprintf("mcsp-val-%d", i)

			if err := toolbox.WriteUnixFrame(pair.guestConn, []byte("info-set "+key+" "+val)); err != nil {
				results[i].err = fmt.Errorf("info-set write: %w", err)
				pair.guestConn.Close()
				return
			}
			setResp, err := toolbox.ReadUnixFrame(pair.guestConn)
			if err != nil {
				results[i].err = fmt.Errorf("info-set read: %w", err)
				pair.guestConn.Close()
				return
			}

			if err := toolbox.WriteUnixFrame(pair.guestConn, []byte("info-get "+key)); err != nil {
				results[i].err = fmt.Errorf("info-get write: %w", err)
				pair.guestConn.Close()
				return
			}
			getResp, err := toolbox.ReadUnixFrame(pair.guestConn)
			if err != nil {
				results[i].err = fmt.Errorf("info-get read: %w", err)
				pair.guestConn.Close()
				return
			}

			pair.guestConn.Close()
			select {
			case <-bridgeDone:
			case <-time.After(5 * time.Second):
				t.Errorf("bridge %d stuck after guest close", i)
			}

			results[i] = result{
				setResp: string(setResp),
				getResp: string(getResp),
			}
		}()
	}
	wg.Wait()

	for i, r := range results {
		require.NoError(t, r.err, "connection %d", i)
		require.Equal(t, "1 ", r.setResp, "connection %d info-set response", i)
		require.Equal(t, "1 mcsp-val-"+fmt.Sprint(i), r.getResp, "connection %d info-get response", i)
	}
}

// TestVMCI_MultipleConnections_DifferentPorts verifies that connections to
// different vsock ports are dispatched to different VMCIPortHandlers.
//
// Port 976  → GuestRPC bridge (info-set / info-get).
// Port 12345 → custom echo handler registered via vi.reg.
func TestVMCI_MultipleConnections_DifferentPorts(t *testing.T) {
		env := newVCSIMEnv(t)

	vmObj := firstVM(env.simCtx)
	require.NotNil(t, vmObj)

	_, vi := newTestBridge(t, "-mcdp", vmObj, env.simCtx)

	// Register a custom echo handler on port 12345.
	const customPort = uint32(12345)
	const echoMsg = "hello-custom-port"
	customDone := make(chan error, 1)

	vi.reg.register(customPort, func(_ string, hostFd int, _, _ uint32) {
		f := os.NewFile(uintptr(hostFd), "vmci-echo")
		conn, err := net.FileConn(f)
		f.Close()
		if err != nil {
			customDone <- fmt.Errorf("FileConn: %w", err)
			return
		}
		defer conn.Close()

		buf, err := toolbox.ReadUnixFrame(conn)
		if err != nil {
			customDone <- fmt.Errorf("ReadUnixFrame: %w", err)
			return
		}
		if err := toolbox.WriteUnixFrame(conn, buf); err != nil {
			customDone <- fmt.Errorf("WriteUnixFrame echo: %w", err)
			return
		}
		customDone <- nil
	})

	// Port 976: GuestRPC get/set via direct bridge call.
	t.Run("port976-guestrpc", func(t *testing.T) {
		hostFd, guestConn := socketpairConn(t)
		bridgeDone := runBridge(vi, hostFd)

		resp := rpcRequest(t, guestConn, "info-set guestinfo.mcdp.port976 works")
		require.Equal(t, "1 ", resp)
		resp = rpcRequest(t, guestConn, "info-get guestinfo.mcdp.port976")
		require.Equal(t, "1 works", resp)

		guestConn.Close()
		select {
		case <-bridgeDone:
		case <-time.After(5 * time.Second):
			t.Fatal("port-976 bridge goroutine stuck after guest close")
		}
	})

	// Port 12345: custom handler looked up from registry and called with a socketpair.
	t.Run("port12345-custom-echo", func(t *testing.T) {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
		require.NoError(t, err)

		f := os.NewFile(uintptr(fds[1]), "custom-guest")
		guestConn, err := net.FileConn(f)
		f.Close()
		require.NoError(t, err)
		defer guestConn.Close()

		h := vi.reg.lookup(customPort)
		require.NotNil(t, h, "handler for port %d must be registered", customPort)
		go h("test-vm", fds[0], 2, customPort)

		require.NoError(t, toolbox.WriteUnixFrame(guestConn, []byte(echoMsg)))
		got, err := toolbox.ReadUnixFrame(guestConn)
		require.NoError(t, err)
		require.Equal(t, echoMsg, string(got), "echo handler must return exact message")

		guestConn.Close()
		select {
		case handlerErr := <-customDone:
			require.NoError(t, handlerErr, "echo handler must exit cleanly")
		case <-time.After(5 * time.Second):
			t.Fatal("echo handler goroutine stuck after guest close")
		}
	})
}

// ── Lifecycle / cleanup tests ─────────────────────────────────────────────────

// TestVMCI_Stop_CleansUp verifies that Stop() closes all tracked seccompFds
// and that WaitGroup.Wait() completes — no goroutine or fd leaks.
//
// This test constructs a vsockIntercept with a real unix listener and a fake
// seccompFd (a socketpair end) in vi.seccompFds, then calls Stop() and verifies
// that the fd is removed from the map and the underlying fd is closed (EBADF on
// double-close).
func TestVMCI_Stop_CleansUp(t *testing.T) {
	tmpSock := filepath.Join(os.TempDir(),
		fmt.Sprintf("vmci-stop-test-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { os.Remove(tmpSock) })

	ln, err := net.Listen("unix", tmpSock)
	require.NoError(t, err)

	vi := newVsockIntercept("vm-stop-test", tmpSock, "", "")
	vi.ln = ln

	// Simulate a live seccompFd by putting one end of a socketpair into the map.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err)
	t.Cleanup(func() { syscall.Close(fds[1]) }) // close guest end; test owns it

	vi.seccompFdsMu.Lock()
	vi.seccompFds[fds[0]] = struct{}{}
	vi.seccompFdsMu.Unlock()

	// Start serve() so wg.Wait() inside Stop() has a goroutine to wait for.
	vi.wg.Add(1)
	go func() {
		defer vi.wg.Done()
		vi.serve()
	}()

	stopDone := make(chan struct{})
	go func() {
		vi.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not complete within 5 s — goroutine or WaitGroup leak")
	}

	// seccompFds map must be empty after Stop().
	vi.seccompFdsMu.Lock()
	_, stillTracked := vi.seccompFds[fds[0]]
	vi.seccompFdsMu.Unlock()
	require.False(t, stillTracked, "Stop() must remove fd from seccompFds map")

	// A second close on fds[0] must return EBADF — confirming Stop() closed it.
	closeErr := syscall.Close(fds[0])
	require.ErrorIs(t, closeErr, syscall.EBADF,
		"seccompFd must have been closed by Stop(); double-close must return EBADF")
}
