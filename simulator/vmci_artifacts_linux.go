// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package simulator

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

var (
	vmciArtifactsOnce         sync.Once
	vmciArtifactsGuestPath string
	vmciArtifactsToolboxPath  string
	vmciArtifactsErr          error
)

// buildVmciArtifacts builds the Go binaries needed for VMCI simulation once per
// process and returns the paths to:
//   - guestBinPath:    vmci-guest  (test agent binary; injected at /vmci-guest)
//   - toolboxBinPath:  toolbox     (govmomi/toolbox binary; injected as /usr/bin/vmware-rpctool)
//
// The function is idempotent and thread-safe.  It is called automatically
// inside simVM.start() when RUN.vmci=true — callers do not need to build or
// inject either binary explicitly.
//
// Both builds require only the Go toolchain.
func buildVmciArtifacts() (guestBinPath, toolboxBinPath string, err error) {
	vmciArtifactsOnce.Do(func() {
		dir, mkErr := os.MkdirTemp("", "vcsim-vmci-artifacts-*")
		if mkErr != nil {
			vmciArtifactsErr = mkErr
			return
		}

		// Build the vmci-guest static binary.  Injected at /vmci-guest for
		// govmomi test subcommands (grpc-set, grpc-get, bidi, …).
		guestBin := filepath.Join(dir, "vmci-guest")
		goBuild := exec.Command(
			"go", "build",
			"-o", guestBin,
			"github.com/vmware/govmomi/simulator/testdata/vmci-guest",
		)
		goBuild.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS=linux",
			"GOARCH=amd64",
		)
		if out, buildErr := goBuild.CombinedOutput(); buildErr != nil {
			vmciArtifactsErr = fmt.Errorf("vmci-guest build: %w\n%s", buildErr, out)
			return
		}
		vmciArtifactsGuestPath = guestBin
		log.Printf("vmci-artifacts: built vmci-guest at %s", guestBin)

		// Build the govmomi/toolbox binary.  Injected at /usr/bin/vmware-rpctool
		// so cloud-init and other guests can write/read guestinfo via AF_VSOCK +
		// DataMap framing without touching the VMware x86 backdoor instruction.
		toolboxBin := filepath.Join(dir, "toolbox")
		toolboxBuild := exec.Command(
			"go", "build",
			"-o", toolboxBin,
			"github.com/vmware/govmomi/toolbox/toolbox",
		)
		toolboxBuild.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS=linux",
			"GOARCH=amd64",
		)
		if out, buildErr := toolboxBuild.CombinedOutput(); buildErr != nil {
			// Non-fatal: toolbox failure only skips the /usr/bin/vmware-rpctool
			// auto-injection.  Tests can still inject the binary explicitly via
			// RUN.volume.  vmci-guest (the test agent) is always required; its
			// build failure is fatal (sets vmciArtifactsErr) and prevents any
			// injection.
			log.Printf("vmci-artifacts: toolbox build failed (%v); vmware-rpctool auto-injection skipped\n%s", buildErr, out)
		} else {
			vmciArtifactsToolboxPath = toolboxBin
			log.Printf("vmci-artifacts: built toolbox at %s", toolboxBin)
		}
	})
	return vmciArtifactsGuestPath, vmciArtifactsToolboxPath, vmciArtifactsErr
}

// VmciToolboxBinaryPath returns the host path of the govmomi/toolbox static
// binary built by buildVmciArtifacts.  It is auto-injected as
// /usr/bin/vmware-rpctool in every container-backed VM with RUN.vmci=true.
//
// Callers that also want to replace /usr/bin/vmtoolsd (e.g. supervisor-adm
// integration tests that need the bootstrapper to write guestinfo via the
// toolbox binary) can obtain the path here and add a RUN.volume.<label>
// ExtraConfig entry:
//
//	"RUN.volume.vmtoolsd": simulator.VmciToolboxBinaryPath() + ":/usr/bin/vmtoolsd:ro"
//
// Returns "" if the build failed (RUN.vmci containers still work via the
// auto-injected /usr/bin/vmware-rpctool, but /usr/bin/vmtoolsd callers will
// fall back to whatever is in the container image).
func VmciToolboxBinaryPath() string {
	_, toolboxPath, _ := buildVmciArtifacts()
	return toolboxPath
}
