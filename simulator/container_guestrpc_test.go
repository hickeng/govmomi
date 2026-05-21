// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

package simulator

// Phase 3 integration tests: real container writes guestinfo via the GuestRPC
// unix socket; PropertyCollector sees the change.
//
// Phase 5 integration test: real container writes guestinfo via AF_VSOCK
// syscalls → seccomp intercept → socketpair bridge → GuestRPC server.
// Exercises the complete vsock interception path end-to-end.
//
// Requires Docker (or podman aliased as docker) on Linux.
// Skip gate: test.HasDocker().

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/test"
	"github.com/vmware/govmomi/vim25/types"
)

// buildStaticBinary cross-compiles pkg as a static linux/amd64 binary written
// to a temp dir.  Returns the output path.
//
// Skips the test if the host OS is not Linux.  Fails (not skips) for build
// errors on Linux, since those indicate a genuine regression rather than a
// missing cross-compilation toolchain.
func buildStaticBinary(t *testing.T, pkg, name string) string {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("container integration test requires Linux")
	}

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, name)

	cmd := exec.Command("go", "build",
		"-o", outPath,
		"-ldflags", "-w -s",
		pkg)
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", name, err, out)
	}

	require.NoError(t, os.Chmod(outPath, fs.FileMode(0755)))
	return outPath
}

// buildVsockTestBinary builds the Component A (unix socket) test binary.
func buildVsockTestBinary(t *testing.T) string {
	return buildStaticBinary(t, "github.com/vmware/govmomi/simulator/testdata/vsock-test", "vsock-test")
}

// buildVmciGuestBinary builds the combined VMCI/vsock test agent binary.
// This binary covers all vsock-intercept scenarios and replaces the former
// vsock-test-intercept binary.
func buildVmciGuestBinary(t *testing.T) string {
	return buildStaticBinary(t, "github.com/vmware/govmomi/simulator/testdata/vmci-guest", "vmci-guest")
}

// TestContainerGuestRPC_RoundTrip is the Phase 3 integration gate:
// a real container process writes guestinfo via the GuestRPC unix socket, and
// the test verifies the value appears in ExtraConfig via PropertyCollector.
//
// Container setup:
//   - image:   alpine (small, available, shell included)
//   - command: sh -c "/vsock-test --roundtrip guestinfo.from.container hello && sleep 9999"
//   - volumes: <vsock-test binary>:/vsock-test:ro  (injected)
//   - RUN.vmci=true  → GuestRPC server started; socket bind-mounted at /run/vmware/rpc.sock
func TestContainerGuestRPC_RoundTrip(t *testing.T) {
	if !test.HasDocker() {
		t.Skip("requires docker or podman (aliased as docker) on linux")
	}

	vsockTestBin := buildVsockTestBinary(t)

	goCtx := context.Background()
	m := VPX()
	defer m.Remove()
	require.NoError(t, m.Create())
	s := m.Service.NewServer()
	defer s.Close()

	c, err := govmomi.NewClient(goCtx, s.URL, true)
	require.NoError(t, err)

	finder := find.NewFinder(c.Client)
	pool, err := finder.ResourcePool(goCtx, "DC0_H0/Resources")
	require.NoError(t, err)
	dc, err := finder.Datacenter(goCtx, "DC0")
	require.NoError(t, err)

	const key = "guestinfo.from.container"
	const val = "hello-from-container"
	cmd := fmt.Sprintf(
		`/vsock-test --socket %s --roundtrip %s %s && sleep 9999`,
		GuestRPCSocketName, key, val,
	)

	spec := types.VirtualMachineConfigSpec{
		Name: "guestrpc-integration-test",
		Files: &types.VirtualMachineFileInfo{
			VmPathName: "[LocalDS_0] guestrpc-integration-test",
		},
		ExtraConfig: []types.BaseOptionValue{
			&types.OptionValue{Key: ContainerBackingOptionKey, Value: fmt.Sprintf(`["alpine","sh","-c",%q]`, cmd)},
			&types.OptionValue{Key: "RUN.vmci", Value: "true"},
			&types.OptionValue{Key: "RUN.volume.vsock-test", Value: vsockTestBin + ":/vsock-test:ro"},
		},
	}

	require.NoError(t, test.ApplyContainerRuntimeDefaults(&spec))

	f, err := dc.Folders(goCtx)
	require.NoError(t, err)

	task, err := f.VmFolder.CreateVM(goCtx, spec, pool, nil)
	require.NoError(t, err)

	info, err := task.WaitForResult(goCtx, nil)
	require.NoError(t, err)

	vmRef := info.Result.(types.ManagedObjectReference)
	vm := object.NewVirtualMachine(c.Client, vmRef)

	powerTask, err := vm.PowerOn(goCtx)
	require.NoError(t, err)
	require.NoError(t, powerTask.Wait(goCtx))

	// Inline poll — this test predates newVCSIMEnv so we keep the explicit client.
	env := &vcSimEnv{goCtx: goCtx, simCtx: m.Service.Context, pc: property.DefaultCollector(c.Client)}
	pollExtraConfig(t, env, vmRef, key, val, 30*time.Second)

	offTask, err := vm.PowerOff(goCtx)
	require.NoError(t, err)
	_ = offTask.Wait(goCtx)
}

// TestContainerGuestRPC_MultiVM verifies that N concurrent container-backed VMs
// each write independent guestinfo values and neither VM can read the other's data.
func TestContainerGuestRPC_MultiVM(t *testing.T) {
	if !test.HasDocker() {
		t.Skip("requires docker or podman (aliased as docker) on linux")
	}

	vsockTestBin := buildVsockTestBinary(t)

	goCtx := context.Background()
	m := VPX()
	defer m.Remove()
	require.NoError(t, m.Create())
	s := m.Service.NewServer()
	defer s.Close()

	c, err := govmomi.NewClient(goCtx, s.URL, true)
	require.NoError(t, err)

	finder := find.NewFinder(c.Client)
	pool, err := finder.ResourcePool(goCtx, "DC0_H0/Resources")
	require.NoError(t, err)
	dc, err := finder.Datacenter(goCtx, "DC0")
	require.NoError(t, err)
	f, err := dc.Folders(goCtx)
	require.NoError(t, err)

	env := &vcSimEnv{goCtx: goCtx, simCtx: m.Service.Context, pc: property.DefaultCollector(c.Client)}

	const n = 2
	type vmEntry struct {
		ref types.ManagedObjectReference
		vm  *object.VirtualMachine
		key string
		val string
	}

	var vms []vmEntry
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("guestinfo.multivm.vm%d", i)
		val := fmt.Sprintf("vm%d-hello", i)
		cmd := fmt.Sprintf(
			`/vsock-test --socket %s --roundtrip %s %s && sleep 9999`,
			GuestRPCSocketName, key, val,
		)
		spec := types.VirtualMachineConfigSpec{
			Name: fmt.Sprintf("guestrpc-multivm-%d", i),
			Files: &types.VirtualMachineFileInfo{
				VmPathName: fmt.Sprintf("[LocalDS_0] guestrpc-multivm-%d", i),
			},
			ExtraConfig: []types.BaseOptionValue{
				&types.OptionValue{Key: ContainerBackingOptionKey, Value: fmt.Sprintf(`["alpine","sh","-c",%q]`, cmd)},
				&types.OptionValue{Key: "RUN.vmci", Value: "true"},
				&types.OptionValue{Key: "RUN.volume.vsock-test", Value: vsockTestBin + ":/vsock-test:ro"},
			},
		}
		require.NoError(t, test.ApplyContainerRuntimeDefaults(&spec))

		task, err := f.VmFolder.CreateVM(goCtx, spec, pool, nil)
		require.NoError(t, err)
		info, err := task.WaitForResult(goCtx, nil)
		require.NoError(t, err)

		ref := info.Result.(types.ManagedObjectReference)
		vm := object.NewVirtualMachine(c.Client, ref)
		powerTask, err := vm.PowerOn(goCtx)
		require.NoError(t, err)
		require.NoError(t, powerTask.Wait(goCtx))

		vms = append(vms, vmEntry{ref: ref, vm: vm, key: key, val: val})
	}

	for _, entry := range vms {
		pollExtraConfig(t, env, entry.ref, entry.key, entry.val, 30*time.Second)
	}

	for _, entry := range vms {
		offTask, err := entry.vm.PowerOff(goCtx)
		require.NoError(t, err)
		_ = offTask.Wait(goCtx)
	}
}

// TestContainerGuestRPC_VsockIntercept is the Phase 5 integration gate.
// It exercises the COMPLETE vsock path end-to-end:
//
//	AF_VSOCK syscall (socket+connect) in container
//	  → seccomp SCMP_ACT_NOTIFY intercept
//	    → socketpair FD injected into container process
//	      → host-end bridged to per-VM GuestRPC unix socket
//	        → GuestRPC server info-set/info-get
//	          → ExtraConfig updated
//	            → PropertyCollector sees the change
//
// Unlike TestContainerGuestRPC_RoundTrip (which talks to the unix socket
// directly), this test confirms that the seccomp intercept transparently
// redirects AF_VSOCK calls without the container process needing any
// knowledge of the simulation layer.
//
// Uses RUN.vmci=true (canonical key) and the vmci-guest binary
// (grpc-roundtrip subcommand), volume-mounted at container start.
func TestContainerGuestRPC_VsockIntercept(t *testing.T) {
	if !test.HasDocker() {
		t.Skip("requires docker or podman (aliased as docker) on linux")
	}

	interceptBin := buildVmciGuestBinary(t)

	goCtx := context.Background()
	m := VPX()
	defer m.Remove()
	require.NoError(t, m.Create())
	s := m.Service.NewServer()
	defer s.Close()

	c, err := govmomi.NewClient(goCtx, s.URL, true)
	require.NoError(t, err)

	finder := find.NewFinder(c.Client)
	pool, err := finder.ResourcePool(goCtx, "DC0_H0/Resources")
	require.NoError(t, err)
	dc, err := finder.Datacenter(goCtx, "DC0")
	require.NoError(t, err)

	const key = "guestinfo.vsocktest"
	const val = "hello-from-vsock-intercept"

	// Run the grpc-roundtrip subcommand then keep the container alive for the
	// PropertyCollector poll below.
	cmd := fmt.Sprintf(
		`/vmci-guest grpc-roundtrip %s %s && sleep 9999`,
		key, val,
	)

	spec := types.VirtualMachineConfigSpec{
		Name: "guestrpc-vsock-intercept-test",
		Files: &types.VirtualMachineFileInfo{
			VmPathName: "[LocalDS_0] guestrpc-vsock-intercept-test",
		},
		ExtraConfig: []types.BaseOptionValue{
			&types.OptionValue{
				Key:   ContainerBackingOptionKey,
				Value: fmt.Sprintf(`["alpine","sh","-c",%q]`, cmd),
			},
			// RUN.vmci=true enables both the GuestRPC server and the AF_VSOCK seccomp intercept.
			&types.OptionValue{Key: "RUN.vmci", Value: "true"},
			&types.OptionValue{Key: "RUN.volume.vmci-guest", Value: interceptBin + ":/vmci-guest:ro"},
		},
	}

	require.NoError(t, test.ApplyContainerRuntimeDefaults(&spec))

	f, err := dc.Folders(goCtx)
	require.NoError(t, err)

	task, err := f.VmFolder.CreateVM(goCtx, spec, pool, nil)
	require.NoError(t, err)

	info, err := task.WaitForResult(goCtx, nil)
	require.NoError(t, err)

	vmRef := info.Result.(types.ManagedObjectReference)
	vm := object.NewVirtualMachine(c.Client, vmRef)

	powerTask, err := vm.PowerOn(goCtx)
	require.NoError(t, err)
	require.NoError(t, powerTask.Wait(goCtx))

	env := &vcSimEnv{goCtx: goCtx, simCtx: m.Service.Context, pc: property.DefaultCollector(c.Client)}
	pollExtraConfig(t, env, vmRef, key, val, 60*time.Second)

	offTask, err := vm.PowerOff(goCtx)
	require.NoError(t, err)
	_ = offTask.Wait(goCtx)
}
