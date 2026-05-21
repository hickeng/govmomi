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
	"runtime"
	"sync"
)

var (
	vmciArtifactsOnce         sync.Once
	vmciArtifactsGuestPath string
	vmciArtifactsToolboxPath  string
	vmciArtifactsErr          error
)

// artifactsBinDir returns the stable host directory used to cache vmci
// simulation binaries across test invocations.
//
// The directory is simulator/bin/ relative to this source file so that the
// binaries persist between "go test" runs.  When a binary already exists it is
// re-used without invoking "go build", benefiting from Go's incremental build:
// repeated test runs pay the compilation cost only on the first invocation (or
// after sources change and the caller deletes the stale binary).
//
// To force a rebuild, delete the cache directory:
//
//	rm -rf <govmomi>/simulator/bin/
//
// Falls back to os.MkdirTemp when the source path is unavailable (e.g. binaries
// built with -trimpath or deployed outside the source tree).
func artifactsBinDir() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return os.MkdirTemp("", "vcsim-vmci-artifacts-*")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("vmci-artifacts: mkdir %s: %w", dir, err)
	}
	return dir, nil
}

// buildVmciArtifacts returns the paths to the VMCI simulation binaries,
// building them only if they are not already present in the cache directory:
//   - guestBinPath:   vmci-guest  (test agent; injected at /vmci-guest)
//   - toolboxBinPath: toolbox     (govmomi/toolbox; injected as /usr/bin/vmware-rpctool)
//
// The function is idempotent and thread-safe (sync.Once per process).  It is
// called automatically inside simVM.start() when RUN.vmci=true.
func buildVmciArtifacts() (guestBinPath, toolboxBinPath string, err error) {
	vmciArtifactsOnce.Do(func() {
		dir, mkErr := artifactsBinDir()
		if mkErr != nil {
			vmciArtifactsErr = mkErr
			return
		}

		// vmci-guest: test agent binary injected at /vmci-guest.
		// Build failure is fatal — the test agent is always required.
		guestBin := filepath.Join(dir, "vmci-guest")
		if _, statErr := os.Stat(guestBin); os.IsNotExist(statErr) {
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
			log.Printf("vmci-artifacts: built vmci-guest at %s", guestBin)
		} else {
			log.Printf("vmci-artifacts: vmci-guest cached at %s", guestBin)
		}
		vmciArtifactsGuestPath = guestBin

		// toolbox: govmomi/toolbox binary injected at /usr/bin/vmware-rpctool.
		// Build failure is non-fatal — auto-injection is skipped but tests may
		// still inject the binary explicitly via RUN.volume.
		toolboxBin := filepath.Join(dir, "toolbox")
		if _, statErr := os.Stat(toolboxBin); os.IsNotExist(statErr) {
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
				log.Printf("vmci-artifacts: toolbox build failed (%v); vmware-rpctool auto-injection skipped\n%s", buildErr, out)
				return
			}
			log.Printf("vmci-artifacts: built toolbox at %s", toolboxBin)
		} else {
			log.Printf("vmci-artifacts: toolbox cached at %s", toolboxBin)
		}
		vmciArtifactsToolboxPath = toolboxBin
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
