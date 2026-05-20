// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package simulator

// Fast, container-free tests for the vsock bridge (Component B).
//
// These tests replace the full container path in TestContainerGuestRPC_VsockIntercept
// for day-to-day development:
//
//	go test ./simulator/... -run TestGuestRPCBridge -v   # <1 s
//
// Instead of a container + seccomp filter, a raw Unix socketpair is created in
// the test process.  One end (the "host end") is passed to bridgeToGuestRPC
// exactly as the seccomp handler would do; the other end (the "guest end") is
// used by an in-process goroutine that plays vmtoolsd — it writes RPCI frames
// and reads responses using the same 4-byte LE framing that the real vmtoolsd
// uses over AF_VSOCK.
//
// What is tested:
//   - bridgeToGuestRPC correctly forwards data in both directions.
//   - GuestRPCServer.infoSet updates ExtraConfig.
//   - GuestRPCServer.infoGet returns the stored value.
//   - After the guest closes its end, bridgeToGuestRPC exits cleanly (the
//     CloseWrite half-close fix); without this the bridge hangs in wg.Wait().
//   - Multiple concurrent info-set/info-get pairs work correctly.
//   - Multiple concurrent VMs each have an isolated bridge + server.

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vmware/govmomi/toolbox"
)

// newTestBridge creates a GuestRPCServer and a vsockIntercept wired to it,
// starts the server, and returns both along with a cleanup function.
// The cleanup stops the server and removes the socket file.
func newTestBridge(t *testing.T, suffix string, vmObj *VirtualMachine, simCtx *Context) (*GuestRPCServer, *vsockIntercept) {
	t.Helper()

	socketPath := GuestRPCSocketPath(vmObj.Self.Value + suffix)
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	srv := newGuestRPCServer(vmObj, socketPath)
	require.NoError(t, srv.Start(simCtx), "GuestRPCServer.Start")
	t.Cleanup(srv.Stop)

	vi := &vsockIntercept{
		vmUID:            t.Name() + suffix,
		guestRPCSockPath: socketPath,
		reg:              newVMCIPortRegistry(),
	}
	return srv, vi
}

// runBridge starts vi.bridgeToGuestRPC(hostFd) in a goroutine and returns a
// channel that is closed when the bridge goroutine exits.
func runBridge(vi *vsockIntercept, hostFd int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		vi.bridgeToGuestRPC(hostFd)
	}()
	return done
}

// socketpairConn creates an AF_UNIX SOCK_STREAM socketpair and returns
// (hostFd, guestConn).  hostFd is the raw file descriptor for the host end;
// guestConn is a net.Conn wrapping the guest end.
// The caller is responsible for closing guestConn; hostFd ownership transfers
// to bridgeToGuestRPC (it will be closed there via net.FileConn).
func socketpairConn(t *testing.T) (hostFd int, guestConn net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(t, err, "socketpair")

	f := os.NewFile(uintptr(fds[1]), "vsock-guest-end")
	guestConn, err = net.FileConn(f)
	f.Close()
	require.NoError(t, err, "FileConn guest end")

	return fds[0], guestConn
}

// rpcRequest sends a single RPCI frame over conn and returns the raw response
// payload (including the "1 " or "0 " status prefix).
func rpcRequest(t *testing.T, conn net.Conn, cmd string) string {
	t.Helper()
	require.NoError(t, toolbox.WriteUnixFrame(conn, []byte(cmd)), "WriteUnixFrame %q", cmd)
	resp, err := toolbox.ReadUnixFrame(conn)
	require.NoError(t, err, "ReadUnixFrame after %q", cmd)
	return string(resp)
}

// TestGuestRPCBridge_SocketPair is the canonical fast companion to
// TestContainerGuestRPC_VsockIntercept.  It verifies the complete
// bridge + GuestRPC path without any container or seccomp machinery.
func TestGuestRPCBridge_SocketPair(t *testing.T) {
		env := newVCSIMEnv(t)

	vmObj := firstVM(env.simCtx)
	require.NotNil(t, vmObj, "no VMs in test inventory")

	_, vi := newTestBridge(t, "-bridge1", vmObj, env.simCtx)

	hostFd, guestConn := socketpairConn(t)
	bridgeDone := runBridge(vi, hostFd)

	const key = "guestinfo.bridge.inprocess"
	const val = "bridge-works"

	// info-set → GuestRPC must update ExtraConfig and respond "1 ".
	resp := rpcRequest(t, guestConn, "info-set "+key+" "+val)
	require.Equal(t, "1 ", resp, "info-set response")

	// info-get → must return the stored value.
	resp = rpcRequest(t, guestConn, "info-get "+key)
	require.Equal(t, "1 "+val, resp, "info-get response")

	// Close guest end — simulates the container/vmtoolsd process exiting.
	// The bridge must exit cleanly within a few seconds (CloseWrite fix).
	guestConn.Close()
	select {
	case <-bridgeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge goroutine did not exit after guest connection closed " +
			"(CloseWrite half-close missing?)")
	}

	var gotValue string
	env.simCtx.WithLock(vmObj, func() {
		for _, opt := range vmObj.Config.ExtraConfig {
			v := opt.GetOptionValue()
			if v.Key == key {
				gotValue = fmt.Sprintf("%v", v.Value)
				break
			}
		}
	})
	require.Equal(t, val, gotValue, "ExtraConfig must have been updated by info-set via bridge")
}

// TestGuestRPCBridge_MultipleCommands sends several sequential info-set/info-get
// pairs over a single bridge connection to verify the GuestRPC server handles
// persistent connections correctly.
func TestGuestRPCBridge_MultipleCommands(t *testing.T) {
		env := newVCSIMEnv(t)

	vmObj := firstVM(env.simCtx)
	require.NotNil(t, vmObj)

	_, vi := newTestBridge(t, "-bridgemulti", vmObj, env.simCtx)

	hostFd, guestConn := socketpairConn(t)
	bridgeDone := runBridge(vi, hostFd)

	const n = 8
	for i := 0; i < n; i++ {
		k := fmt.Sprintf("guestinfo.multi.key%d", i)
		v := fmt.Sprintf("value%d", i)

		resp := rpcRequest(t, guestConn, "info-set "+k+" "+v)
		require.Equal(t, "1 ", resp, "info-set[%d]", i)

		resp = rpcRequest(t, guestConn, "info-get "+k)
		require.Equal(t, "1 "+v, resp, "info-get[%d]", i)
	}

	guestConn.Close()
	select {
	case <-bridgeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge goroutine stuck after guest close")
	}

	var found int
	env.simCtx.WithLock(vmObj, func() {
		for _, opt := range vmObj.Config.ExtraConfig {
			v := opt.GetOptionValue()
			if strings.HasPrefix(v.Key, "guestinfo.multi.key") {
				found++
			}
		}
	})
	require.Equal(t, n, found, "all %d guestinfo keys must be in ExtraConfig", n)
}

// TestGuestRPCBridge_VMToolsdCommands exercises the additional RPCI commands
// that vmtoolsd sends on startup (tools.capability.*, Capabilities_Register,
// tools.set-state, tools.set.version).  The server must acknowledge all of
// them with "1 " without affecting ExtraConfig.
func TestGuestRPCBridge_VMToolsdCommands(t *testing.T) {
		env := newVCSIMEnv(t)

	vmObj := firstVM(env.simCtx)
	require.NotNil(t, vmObj)

	_, vi := newTestBridge(t, "-bridgevmtools", vmObj, env.simCtx)

	hostFd, guestConn := socketpairConn(t)
	bridgeDone := runBridge(vi, hostFd)

	// Commands vmtoolsd sends on startup — all must be acknowledged.
	startupCmds := []string{
		"tools.capability.hgfs_server toolbox 1",
		"tools.set.version 65536",
		"tools.set-state 2",
		"Capabilities_Register",
	}
	for _, cmd := range startupCmds {
		resp := rpcRequest(t, guestConn, cmd)
		require.Equal(t, "1 ", resp, "startup command %q", cmd)
	}

	// Now do a real guestinfo round-trip.
	resp := rpcRequest(t, guestConn, "info-set guestinfo.vmtools.test alive")
	require.Equal(t, "1 ", resp)

	resp = rpcRequest(t, guestConn, "info-get guestinfo.vmtools.test")
	require.Equal(t, "1 alive", resp)

	guestConn.Close()
	select {
	case <-bridgeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("bridge goroutine stuck")
	}
}

// TestGuestRPCBridge_TwoVMs verifies that two concurrent VMs each have an
// isolated bridge and GuestRPC server — info-set on VM 0 must not be visible
// to VM 1 and vice versa.
func TestGuestRPCBridge_TwoVMs(t *testing.T) {
		env := newVCSIMEnv(t)

	refs := env.simCtx.Map.AllReference("VirtualMachine")
	if len(refs) < 2 {
		t.Skip("need at least 2 VMs in the test inventory")
	}

	type vmHandle struct {
		obj       *VirtualMachine
		vi        *vsockIntercept
		guestConn net.Conn
		done      <-chan struct{}
		key, val  string
	}

	var handles [2]vmHandle
	for i := 0; i < 2; i++ {
		obj := env.simCtx.Map.Get(refs[i].Reference()).(*VirtualMachine)
		_, vi := newTestBridge(t, fmt.Sprintf("-two%d", i), obj, env.simCtx)
		hostFd, gc := socketpairConn(t)
		handles[i] = vmHandle{
			obj:       obj,
			vi:        vi,
			guestConn: gc,
			done:      runBridge(vi, hostFd),
			key:       fmt.Sprintf("guestinfo.two.vm%d", i),
			val:       fmt.Sprintf("vm%d-isolated", i),
		}
	}

	// Each VM sets its own key.
	for _, h := range handles {
		resp := rpcRequest(t, h.guestConn, "info-set "+h.key+" "+h.val)
		require.Equal(t, "1 ", resp)
	}

	// Each VM can get its own key …
	for _, h := range handles {
		resp := rpcRequest(t, h.guestConn, "info-get "+h.key)
		require.Equal(t, "1 "+h.val, resp)
	}

	// … but must NOT see the other VM's key.
	resp0 := rpcRequest(t, handles[0].guestConn, "info-get "+handles[1].key)
	require.Equal(t, "0 No value found", resp0, "VM0 must not see VM1's key")

	resp1 := rpcRequest(t, handles[1].guestConn, "info-get "+handles[0].key)
	require.Equal(t, "0 No value found", resp1, "VM1 must not see VM0's key")

	// Tear down.
	for _, h := range handles {
		h.guestConn.Close()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("bridge for VM %s stuck", h.obj.Name)
		}
	}
}

// TestGuestRPCBridge_CloseWritePropagation is a focused regression test for the
// CloseWrite half-close fix.  It verifies that bridgeToGuestRPC exits quickly
// after the guest connection is closed, even with no data flowing.
func TestGuestRPCBridge_CloseWritePropagation(t *testing.T) {
		env := newVCSIMEnv(t)

	vmObj := firstVM(env.simCtx)
	require.NotNil(t, vmObj)

	_, vi := newTestBridge(t, "-closewrite", vmObj, env.simCtx)

	hostFd, guestConn := socketpairConn(t)
	bridgeDone := runBridge(vi, hostFd)

	// Close immediately without sending any data.
	guestConn.Close()

	select {
	case <-bridgeDone:
		// Pass — bridge exited cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("bridge goroutine did not exit within 5 s after guest close " +
			"(CloseWrite regression)")
	}
}
