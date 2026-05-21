// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package simulator

import "errors"

// buildVmciArtifacts is a no-op stub on non-Linux platforms.
// VMCI artifact builds are only supported on Linux where the seccomp AF_VSOCK
// interception runs.
func buildVmciArtifacts() (guestBinPath, toolboxBinPath string, err error) {
	return "", "", errors.New("vmci-artifacts: only available on linux")
}

// VmciToolboxBinaryPath returns "" on non-Linux platforms where VMCI simulation
// is not supported.
func VmciToolboxBinaryPath() string { return "" }
