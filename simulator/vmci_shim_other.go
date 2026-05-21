// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package simulator

import "errors"

// buildVmciShim is a no-op stub on non-Linux platforms.
// The VMCI shim is only meaningful on Linux where the seccomp AF_VSOCK
// interception runs.
func buildVmciShim() (soPath, confPath, guestBinPath string, err error) {
	return "", "", "", errors.New("vmci-backdoor-shim: only available on linux")
}
