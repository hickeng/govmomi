// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package simulator

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// vmciShimSrc is the C source for the LD_PRELOAD shim embedded at build time.
// The shim overrides VMware backdoor and VMCISock functions so that vmtoolsd
// (and any process that links libvmtools) can run inside an unprivileged
// container without hitting the x86 IN instruction (SIGILL).
//
//go:embed testdata/vmci-backdoor-shim/shim.c
var vmciShimSrc []byte

// systemdDefaultEnvConf is the content of the systemd Manager drop-in that
// propagates LD_PRELOAD to every service spawned by systemd.  Without this,
// systemd clears the inherited environment before launching services, so
// the LD_PRELOAD set on the container's PID1 never reaches vmtoolsd,
// cloud-init, or the supervisor bootstrapper.
const systemdDefaultEnvConf = "[Manager]\nDefaultEnvironment=LD_PRELOAD=/vmci-backdoor-shim.so\n"

var (
	vmciShimOnce        sync.Once
	vmciShimSoPath      string
	vmciShimConfPath    string
	vmciShimGuestBinPath string
	vmciShimErr         error
)

// buildVmciShim compiles the LD_PRELOAD shim once per process and returns the
// paths to:
//   - soPath:      vmci-backdoor-shim.so  (LD_PRELOAD target inside the container)
//   - confPath:    vmci-shim.conf         (systemd DefaultEnvironment drop-in)
//   - guestBinPath vmci-guest             (static binary; also injected as vmware-rpctool)
//
// The function is idempotent and thread-safe.  It is called automatically
// inside simVM.start() when RUN.vmci=true — callers do not need to build or
// inject the shim explicitly.
//
// When gcc is unavailable the LD_PRELOAD shim is skipped (non-fatal); the
// vmci-guest binary still allows vmware-rpctool-compatible RPC.
// The vmci-guest build requires only the Go toolchain (always available).
func buildVmciShim() (soPath, confPath, guestBinPath string, err error) {
	vmciShimOnce.Do(func() {
		dir, mkErr := os.MkdirTemp("", "vcsim-vmci-shim-*")
		if mkErr != nil {
			vmciShimErr = mkErr
			return
		}

		// Build the vmci-guest static binary.  It is injected at two container
		// paths:
		//   /vmci-guest              — used by govmomi tests for get/set/roundtrip
		//   /usr/bin/vmware-rpctool  — overrides the system wrapper; handles
		//                              cloud-init's guestinfo queries without
		//                              needing LD_PRELOAD (the system rpctool may
		//                              be statically linked so LD_PRELOAD never
		//                              applies).
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
			vmciShimErr = fmt.Errorf("vmci-guest build: %w\n%s", buildErr, out)
			return
		}
		vmciShimGuestBinPath = guestBin
		log.Printf("vmci-backdoor-shim: built vmci-guest at %s", guestBin)

		// Compile the LD_PRELOAD C shim (best-effort: requires gcc).
		// Used by dynamically-linked vmtoolsd; skipped silently if gcc is absent.
		if _, lookErr := exec.LookPath("gcc"); lookErr == nil {
			// Write embedded shim.c to the temp directory.
			srcPath := filepath.Join(dir, "shim.c")
			if writeErr := os.WriteFile(srcPath, vmciShimSrc, 0o600); writeErr != nil {
				log.Printf("vmci-backdoor-shim: write shim.c: %v (skipping)", writeErr)
			} else {
				soFile := filepath.Join(dir, "vmci-backdoor-shim.so")
				out, gccErr := exec.Command(
					"gcc", "-shared", "-fPIC", "-O2",
					"-o", soFile, srcPath, "-ldl", "-lc",
				).CombinedOutput()
				if gccErr != nil {
					log.Printf("vmci-backdoor-shim: gcc: %v\n%s (skipping)", gccErr, out)
				} else {
					vmciShimSoPath = soFile
					log.Printf("vmci-backdoor-shim: built %s", soFile)
				}
			}
		} else {
			log.Printf("vmci-backdoor-shim: gcc not found — LD_PRELOAD shim skipped; vmware-rpctool override still active")
		}

		// Write the systemd Manager drop-in that propagates LD_PRELOAD to all
		// services.  Without this, systemd PID1 does not pass its own LD_PRELOAD
		// to child services (vmtoolsd, cloud-init, bootstrapper).
		cfgFile := filepath.Join(dir, "vmci-shim.conf")
		if writeErr := os.WriteFile(cfgFile, []byte(systemdDefaultEnvConf), 0o644); writeErr != nil {
			vmciShimErr = fmt.Errorf("vmci-backdoor-shim: write systemd conf: %w", writeErr)
			return
		}
		vmciShimConfPath = cfgFile
	})
	return vmciShimSoPath, vmciShimConfPath, vmciShimGuestBinPath, vmciShimErr
}
