// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package simulator

// VMCIPortHandler is a no-op stub on non-Linux platforms.
type VMCIPortHandler func(vmUID string, hostFd int, cid, port uint32)

// vmciPortRegistry is a no-op stub on non-Linux platforms.
type vmciPortRegistry struct{}

func newVMCIPortRegistry() *vmciPortRegistry { return &vmciPortRegistry{} }

func (r *vmciPortRegistry) register(_ uint32, _ VMCIPortHandler) {}
func (r *vmciPortRegistry) setDefault(_ VMCIPortHandler)         {}
func (r *vmciPortRegistry) lookup(_ uint32) VMCIPortHandler      { return nil }

// vsockIntercept is a no-op stub on non-Linux platforms.
type vsockIntercept struct {
	vmUID            string
	guestRPCSockPath string
	reg              *vmciPortRegistry
	ready            chan struct{}
}

// Stop is a no-op on non-Linux platforms.
func (vi *vsockIntercept) Stop() {}

// vsockWriteFilterFile returns "" on non-Linux platforms.
func vsockWriteFilterFile(vmUID string) string {
	return ""
}

// newVsockInterceptAndStart returns nil on non-Linux platforms.
// The GuestRPC server (Component A) still works via the bind-mounted unix socket.
func newVsockInterceptAndStart(vmUID, guestRPCSocketPath, filterPath string) *vsockIntercept {
	return nil
}
