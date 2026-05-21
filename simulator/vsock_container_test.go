// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package simulator

// TestVMCI_ContainerBidirectional exercises the full VMCI/vsock interception
// stack using a real container + the vmci-guest test agent binary.
//
// The vmci-guest binary is built once and injected via RUN.volume at container
// start (same mechanism as TestContainerGuestRPC_*).  Individual test scenarios
// are driven via "docker exec", each of which spawns a new process tree in the
// container and causes crun to open a fresh seccompFd connection to the vcsim
// listener — exercising the Phase 6a multi-accept loop.
//
// This test is the primary end-to-end validation of:
//
//   - AF_VSOCK socket() interception (socketpair injection).
//   - connect() dispatch to registered VMCIPortHandlers.
//   - VM→Host GuestRPC (info-set / info-get via port 976).
//   - Host→VM data flow within a custom handler (port 7777).
//   - Guest→Host data flow within the same custom connection.
//   - Bidirectional exchange via a port handler registered after PowerOn.
//   - vsockVI.Stop() shutdown path after container exit.
//
// Requires: Docker (or podman aliased as docker) on Linux, alpine image.
// Skip gate: test.HasDocker().

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/test"
	"github.com/vmware/govmomi/vim25/types"
)

// buildToolboxBinary builds the govmomi/toolbox binary as a static linux/amd64
// binary.  It is the canonical vmtoolsd / vmware-rpctool replacement for
// container-backed VMs in vcsim tests.
// buildToolboxBinary returns the path to the cached govmomi/toolbox binary,
// sharing the build with the simulator's own buildVmciArtifacts (sync.Once).
// This avoids a second independent "go build" when RUN.vmci=true is set,
// which would also trigger buildVmciArtifacts during PowerOn.
func buildToolboxBinary(t *testing.T) string {
	t.Helper()
	_, path, err := buildVmciArtifacts()
	if err != nil {
		t.Skipf("vmci artifact build failed: %v", err)
	}
	if path == "" {
		t.Skip("toolbox binary unavailable (govmomi/toolbox build may have been skipped)")
	}
	return path
}

// dockerExec runs "docker exec containerID args..." and returns trimmed stdout.
// Stderr from docker exec (including podman compatibility warnings) is isolated
// and only included in the failure message, not in the return value.
func dockerExec(t *testing.T, ctx context.Context, containerID string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker",
		append([]string{"exec", containerID}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = ee.Stderr
		}
		t.Fatalf("docker exec %v: %v\nstderr: %s", args, err, stderr)
	}
	return strings.TrimSpace(string(out))
}

// waitForVsockReady returns the vsockIntercept for vmObj, blocking until it is
// non-nil and has signalled readiness (first seccompFd received from crun).
// Fails the test if either condition is not met within deadline.
func waitForVsockReady(t *testing.T, simCtx *Context, vmObj *VirtualMachine, deadline time.Duration) *vsockIntercept {
	t.Helper()

	var vi *vsockIntercept
	simCtx.WithLock(vmObj, func() {
		if vmObj.svm != nil {
			vi = vmObj.svm.vsockVI
		}
	})
	if vi == nil {
		t.Fatal("waitForVsockReady: vsockVI is nil — RUN.vmci not applied?")
	}

	select {
	case <-vi.ready:
		t.Logf("vsock intercept ready (seccompFd received)")
	case <-time.After(deadline):
		t.Fatalf("vsock intercept not ready after %s — crun never connected?", deadline)
	}
	return vi
}

// containerIDFor returns the Docker container ID for vmObj's running container.
func containerIDFor(t *testing.T, simCtx *Context, vmObj *VirtualMachine) string {
	t.Helper()
	var id string
	simCtx.WithLock(vmObj, func() {
		if vmObj.svm != nil && vmObj.svm.c != nil {
			id = vmObj.svm.c.id
		}
	})
	require.NotEmpty(t, id, "container ID must be set after PowerOn")
	return id
}

// readGuestInfoKey reads KEY directly from vmObj's ExtraConfig without going
// through the PropertyCollector.  Must be called with no lock held.
func readGuestInfoKey(simCtx *Context, vmObj *VirtualMachine, key string) string {
	var val string
	simCtx.WithLock(vmObj, func() {
		for _, opt := range vmObj.Config.ExtraConfig {
			ov := opt.GetOptionValue()
			if ov.Key == key {
				val = fmt.Sprintf("%v", ov.Value)
				return
			}
		}
	})
	return val
}

// TestVMCI_ContainerBidirectional is the Phase 6a end-to-end integration test.
func TestVMCI_ContainerBidirectional(t *testing.T) {
	if !test.HasDocker() {
		t.Skip("requires docker or podman (aliased as docker) on linux")
	}

	// ── Build the guest binary ────────────────────────────────────────────
	// The binary is volume-mounted at container start so it is available
	// immediately without a separate docker cp step.
	guestBin := buildStaticBinary(t,
		"github.com/vmware/govmomi/simulator/testdata/vmci-guest",
		"vmci-guest")

	// ── Stand up vcsim ────────────────────────────────────────────────────
	goCtx := context.Background()
	m := VPX()
	defer m.Remove()
	require.NoError(t, m.Create())
	s := m.Service.NewServer()
	defer s.Close()
	simCtx := m.Service.Context

	c, err := govmomi.NewClient(goCtx, s.URL, true)
	require.NoError(t, err)

	finder := find.NewFinder(c.Client)
	pool, err := finder.ResourcePool(goCtx, "DC0_H0/Resources")
	require.NoError(t, err)
	dc, err := finder.Datacenter(goCtx, "DC0")
	require.NoError(t, err)
	f, err := dc.Folders(goCtx)
	require.NoError(t, err)

	// ── Create container-backed VM ────────────────────────────────────────
	// The container main command uses a SIGTERM trap so "docker stop" completes
	// in < 1 s.  BusyBox sleep ignores SIGTERM; the sh trap catches it.
	// RUN.vmci enables both the GuestRPC server (port 976) and the AF_VSOCK
	// seccomp intercept.  RUN.volume injects vmci-guest at container start so
	// every docker exec has the binary available without a docker cp step.
	spec := types.VirtualMachineConfigSpec{
		Name: "vmci-bidi-test",
		Files: &types.VirtualMachineFileInfo{
			VmPathName: "[LocalDS_0] vmci-bidi-test",
		},
		ExtraConfig: []types.BaseOptionValue{
			&types.OptionValue{
				Key:   ContainerBackingOptionKey,
				Value: `["alpine","sh","-c","trap exit SIGTERM; sleep infinity & wait"]`,
			},
			&types.OptionValue{Key: "RUN.vmci", Value: "true"},
			&types.OptionValue{Key: "RUN.volume.vmci-guest", Value: guestBin + ":/vmci-guest:ro"},
		},
	}
	require.NoError(t, test.ApplyContainerRuntimeDefaults(&spec))

	task, err := f.VmFolder.CreateVM(goCtx, spec, pool, nil)
	require.NoError(t, err)
	info, err := task.WaitForResult(goCtx, nil)
	require.NoError(t, err)

	vmRef := info.Result.(types.ManagedObjectReference)
	vm := object.NewVirtualMachine(c.Client, vmRef)

	// ── PowerOn — starts the container with vmci-guest already mounted ────
	powerTask, err := vm.PowerOn(goCtx)
	require.NoError(t, err)
	require.NoError(t, powerTask.Wait(goCtx))

	vmObj := simCtx.Map.Get(vmRef).(*VirtualMachine)

	// ── Wait for seccomp intercept to be active ───────────────────────────
	vi := waitForVsockReady(t, simCtx, vmObj, 30*time.Second)

	containerID := containerIDFor(t, simCtx, vmObj)

	// ── Register bidirectional handler on port 7777 ───────────────────────
	// Must happen before "docker exec bidi" so the handler is present when the
	// guest binary issues connect(AF_VSOCK, CID=2, port=7777).
	const bidiPort = uint32(7777)
	const hostMsg = "H2G:ping"
	const guestMsg = "G2H:pong"

	bidiResult := make(chan error, 1)
	vi.reg.register(bidiPort, func(_ string, hostFd int, _, _ uint32) {
		defer func() {
			if r := recover(); r != nil {
				select {
				case bidiResult <- fmt.Errorf("handler panic: %v", r):
				default:
				}
			}
		}()

		hostFile := os.NewFile(uintptr(hostFd), "vmci-bidi-host")
		conn, err := net.FileConn(hostFile)
		hostFile.Close()
		if err != nil {
			select {
			case bidiResult <- fmt.Errorf("FileConn: %w", err):
			default:
			}
			return
		}
		defer conn.Close()

		if _, err := fmt.Fprintln(conn, hostMsg); err != nil {
			select {
			case bidiResult <- fmt.Errorf("write H2G: %w", err):
			default:
			}
			return
		}

		sc := bufio.NewScanner(conn)
		if !sc.Scan() {
			scanErr := sc.Err()
			if scanErr == nil {
				scanErr = io.EOF
			}
			select {
			case bidiResult <- fmt.Errorf("scan G2H: %w", scanErr):
			default:
			}
			return
		}
		got := sc.Text()
		if got != guestMsg {
			select {
			case bidiResult <- fmt.Errorf("G2H: got %q, want %q", got, guestMsg):
			default:
			}
			return
		}
		select {
		case bidiResult <- nil:
		default:
		}
	})

	// ── TEST 1: VM→Host GuestRPC info-set via AF_VSOCK ────────────────────
	t.Run("grpc-set", func(t *testing.T) {
		const key = "guestinfo.vmci.container.test"
		const val = "agent-ok"

		dockerExec(t, goCtx, containerID, "/vmci-guest", "grpc-set", key, val)

		got := readGuestInfoKey(simCtx, vmObj, key)
		require.Equal(t, val, got,
			"guestinfo key %q must be set after grpc-set exec", key)
	})

	// ── TEST 2: Bidirectional exchange via custom port handler ────────────
	t.Run("bidi", func(t *testing.T) {
		dockerExec(t, goCtx, containerID,
			"/vmci-guest", "bidi",
			fmt.Sprint(bidiPort), hostMsg, guestMsg)

		select {
		case handlerErr := <-bidiResult:
			require.NoError(t, handlerErr, "bidi port handler must succeed")
		case <-time.After(10 * time.Second):
			t.Fatal("bidi handler did not complete within 10 s")
		}
	})

	// ── TEST 3: VM→Host GuestRPC info-get via AF_VSOCK ───────────────────
	// Each docker exec → new crun conn → new seccompFd scope → new socket/connect cycle.
	t.Run("grpc-get", func(t *testing.T) {
		const key = "guestinfo.vmci.container.test"
		const want = "agent-ok"

		got := dockerExec(t, goCtx, containerID, "/vmci-guest", "grpc-get", key)
		require.Equal(t, want, got,
			"grpc-get output must match the value set by grpc-set")
	})

	// ── TEST 4: Stop path ─────────────────────────────────────────────────
	// PowerOff → svm.c.stop() (docker stop) → svm.vsockVI.Stop().
	// c.stop() is called before vsockVI.Stop() so container processes exit
	// first; the SIGTERM trap ensures docker stop completes in < 1 s.
	// vsockVI.Stop() has a 15 s belt-and-suspenders timeout for goroutines
	// blocked in SECCOMP_IOCTL_NOTIF_RECV (crun cleanup may outlive the container).
	t.Run("stop", func(t *testing.T) {
		stopCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		offTask, err := vm.PowerOff(stopCtx)
		require.NoError(t, err)
		require.NoError(t, offTask.Wait(stopCtx),
			"PowerOff must complete within 60 s — vsockVI.Stop() may have deadlocked")

		t.Logf("PowerOff completed; vsockVI.Stop() did not deadlock")

		vi.stopMu.Lock()
		stopped := vi.stopped
		vi.stopMu.Unlock()
		require.True(t, stopped, "vsockIntercept must be marked stopped after PowerOff")
	})
}

// TestVMCI_ToolboxBinary_GuestInfoRoundTrip validates that the govmomi/toolbox
// binary, when volume-overlaid as /usr/bin/vmtoolsd and /usr/bin/vmware-rpctool
// in a container-backed VM, correctly reads and writes guestinfo through the
// vcsim AF_VSOCK intercept + GuestRPC server.
//
// This test is the acceptance gate for D-97-14 and FU-97-10:
//
//   - D-97-14: toolbox binary is the vmtoolsd/vmware-rpctool replacement.
//   - FU-97-10 (CLOSED): toolbox now supports DataMap framing via VsockChannel,
//     making the binary compatible with both vcsim (AF_VSOCK intercept) and
//     real ESX hypervisors (native AF_VSOCK).
//
// Subtests:
//  1. vmtoolsd-info-set: info-set KEY VAL → value visible in ExtraConfig.
//  2. vmtoolsd-info-get: info-get KEY → bare value printed to stdout, exit 0.
//  3. vmware-rpctool-info-get: raw "1 VALUE" response, exit 0 (cloud-init contract).
//  4. vmtoolsd-info-get-missing: missing key → exit 1, no stdout (cloud-init contract).
//  5. stop: PowerOff completes cleanly, vsockVI stopped.
func TestVMCI_ToolboxBinary_GuestInfoRoundTrip(t *testing.T) {
	if !test.HasDocker() {
		t.Skip("requires docker or podman (aliased as docker) on linux")
	}

	// ── Build the toolbox binary ──────────────────────────────────────────
	toolboxBin := buildToolboxBinary(t)

	// ── Stand up vcsim ────────────────────────────────────────────────────
	goCtx := context.Background()
	m := VPX()
	defer m.Remove()
	require.NoError(t, m.Create())
	s := m.Service.NewServer()
	defer s.Close()
	simCtx := m.Service.Context

	c, err := govmomi.NewClient(goCtx, s.URL, true)
	require.NoError(t, err)

	finder := find.NewFinder(c.Client)
	pool, err := finder.ResourcePool(goCtx, "DC0_H0/Resources")
	require.NoError(t, err)
	dc, err := finder.Datacenter(goCtx, "DC0")
	require.NoError(t, err)
	f, err := dc.Folders(goCtx)
	require.NoError(t, err)

	// ── Create container-backed VM ────────────────────────────────────────
	// Overlay the toolbox binary as /usr/bin/vmtoolsd (explicit RUN.volume).
	// /usr/bin/vmware-rpctool is auto-injected by buildVmciArtifacts (RUN.vmci=true).
	// Both dispatch on filepath.Base(os.Args[0]).
	const key = "guestinfo.toolbox-roundtrip"
	const val = "hello-from-toolbox"

	spec := types.VirtualMachineConfigSpec{
		Name:  "toolbox-roundtrip-test",
		Files: &types.VirtualMachineFileInfo{VmPathName: "[LocalDS_0] toolbox-roundtrip-test"},
		ExtraConfig: []types.BaseOptionValue{
			&types.OptionValue{
				Key:   ContainerBackingOptionKey,
				Value: `["alpine","sh","-c","trap exit SIGTERM; sleep infinity & wait"]`,
			},
			&types.OptionValue{Key: "RUN.vmci", Value: "true"},
			// Inject the toolbox binary as /usr/bin/vmtoolsd so vmtoolsd --cmd
			// dispatches on filepath.Base(os.Args[0]) = "vmtoolsd".
			// /usr/bin/vmware-rpctool is auto-injected by buildVmciArtifacts when
			// RUN.vmci=true; no explicit RUN.volume entry needed for it.
			&types.OptionValue{
				Key:   "RUN.volume.vmtoolsd",
				Value: toolboxBin + ":/usr/bin/vmtoolsd:ro",
			},
		},
	}
	require.NoError(t, test.ApplyContainerRuntimeDefaults(&spec))

	task, err := f.VmFolder.CreateVM(goCtx, spec, pool, nil)
	require.NoError(t, err)
	info, err := task.WaitForResult(goCtx, nil)
	require.NoError(t, err)

	vmRef := info.Result.(types.ManagedObjectReference)
	vm := object.NewVirtualMachine(c.Client, vmRef)

	powerTask, err := vm.PowerOn(goCtx)
	require.NoError(t, err)
	require.NoError(t, powerTask.Wait(goCtx))

	vmObj := simCtx.Map.Get(vmRef).(*VirtualMachine)
	vi := waitForVsockReady(t, simCtx, vmObj, 30*time.Second)
	containerID := containerIDFor(t, simCtx, vmObj)

	// ── TEST 1: vmtoolsd --cmd info-set ───────────────────────────────────
	t.Run("vmtoolsd-info-set", func(t *testing.T) {
		// info-set exits 0 and produces no stdout on success.
		dockerExec(t, goCtx, containerID,
			"vmtoolsd", "--cmd", "info-set "+key+" "+val)

		got := readGuestInfoKey(simCtx, vmObj, key)
		require.Equal(t, val, got,
			"ExtraConfig key %q must be set after vmtoolsd --cmd info-set", key)
	})

	// ── TEST 2: vmtoolsd --cmd info-get ───────────────────────────────────
	t.Run("vmtoolsd-info-get", func(t *testing.T) {
		// info-get exits 0 and prints the bare value (no "1 " prefix).
		out := dockerExec(t, goCtx, containerID,
			"vmtoolsd", "--cmd", "info-get "+key)
		require.Equal(t, val, out,
			"vmtoolsd --cmd info-get must print bare value")
	})

	// ── TEST 3: vmware-rpctool info-get ───────────────────────────────────
	t.Run("vmware-rpctool-info-get", func(t *testing.T) {
		// vmware-rpctool prints the raw "1 VALUE" or "0 ..." response and
		// always exits 0 on a successful channel round-trip.  cloud-init
		// parses the "1 " prefix itself.
		out := dockerExec(t, goCtx, containerID,
			"vmware-rpctool", "info-get "+key)
		require.Equal(t, "1 "+val, out,
			"vmware-rpctool info-get must print raw '1 VALUE' response")
	})

	// ── TEST 4: vmtoolsd info-get missing key → exit 1 ───────────────────
	// Verifies the exit-code contract that cloud-init DataSourceVMware depends on:
	// exit 0 = key found, exit 1 = key missing or channel error.
	t.Run("vmtoolsd-info-get-missing", func(t *testing.T) {
		cmd := exec.CommandContext(goCtx, "docker",
			"exec", containerID,
			"vmtoolsd", "--cmd", "info-get guestinfo.nonexistent.key")
		out, err := cmd.Output()

		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr,
			"vmtoolsd info-get for a missing key must exit non-zero")
		require.Equal(t, 1, exitErr.ExitCode(),
			"vmtoolsd info-get for a missing key must exit 1")
		require.Empty(t, strings.TrimSpace(string(out)),
			"vmtoolsd info-get for a missing key must produce no stdout")
	})

	// ── TEST 5: Stop path ─────────────────────────────────────────────────
	// Mirrors the identical check in TestVMCI_ContainerBidirectional:
	// vsockVI.Stop() must be called and vi.stopped must be true after PowerOff.
	t.Run("stop", func(t *testing.T) {
		stopCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		offTask, err := vm.PowerOff(stopCtx)
		require.NoError(t, err)
		require.NoError(t, offTask.Wait(stopCtx),
			"PowerOff must complete within 60 s — vsockVI.Stop() may have deadlocked")

		t.Logf("PowerOff completed; vsockVI.Stop() did not deadlock")

		vi.stopMu.Lock()
		stopped := vi.stopped
		vi.stopMu.Unlock()
		require.True(t, stopped, "vsockIntercept must be marked stopped after PowerOff")
	})
}
