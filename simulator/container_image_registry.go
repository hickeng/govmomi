// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

// Container Image Registry for VM-to-OCI mapping
//
// This file implements a general-purpose registry that maps VM configuration
// attributes to OCI container images. It is consulted at PowerOn time and
// automatically injects the RUN.container ExtraConfig key when a match is found,
// enabling container-backed simulation without requiring modifications to the
// production code being tested.
//
// # Design Intent
//
// The registry intentionally decouples OCI image assignment from VM creation
// mechanisms. Whether a VM is created via OVF import, linked-clone, fast-deploy
// (datastore path reference), or direct VM creation, the same lookup applies at
// PowerOn time. This makes the registry useful across all simulation scenarios.
//
// # Matching
//
// Entries are evaluated in registration order. The first match wins.
//
//   - VMNameGlob:   matched against vm.Config.Name using path.Match glob syntax.
//     Use "*" to match any name, "bootstrap-*" for prefix matching.
//
//   - DiskPathGlob: matched against the FileName of any VirtualDisk flat backing.
//     Typical format: "[datastore1] vmName/disk-0.vmdk". Useful for linked-clone
//     scenarios where the base disk path is the stable identifier.
//
// At least one of VMNameGlob or DiskPathGlob must be set per entry.
//
// # Example: OVF Deployment
//
//	reg.ContainerImages.Register(simulator.ContainerImageEntry{
//	    VMNameGlob: "bootstrap-vm",
//	    OCIImage:   "vkr-test:latest",
//	})
//
// # Example: Linked-Clone / Fast-Deploy
//
//	reg.ContainerImages.Register(simulator.ContainerImageEntry{
//	    DiskPathGlob: "[datastore*] base-image/disk-0.vmdk",
//	    OCIImage:     "vkr-test:latest",
//	})
package simulator

import (
	"path"
	"sync"

	"github.com/vmware/govmomi/vim25/types"
)

// ContainerImageEntry maps VM configuration attributes to an OCI container image.
// At least one of VMNameGlob or DiskPathGlob must be non-empty.
type ContainerImageEntry struct {
	// VMNameGlob is a path.Match glob pattern matched against vm.Config.Name.
	VMNameGlob string

	// DiskPathGlob is a path.Match glob pattern matched against the FileName of
	// any VirtualDisk flat backing present in the VM config. Typical format:
	// "[datastore1] vmName/disk-0.vmdk".
	DiskPathGlob string

	// OCIImage is the container image reference to inject as RUN.container when
	// this entry matches. E.g. "nginx:latest", "vkr-test:latest".
	OCIImage string

	// ExtraConfig holds additional key/value pairs to inject into the VM's
	// ExtraConfig alongside RUN.container. Use this for container-runtime
	// tuning that must be set per-VM without modifying the code under test.
	// Common examples:
	//   "RUN.mountdmi":       "false"  — disable /sys/class/dmi mount for rootless podman
	//   "RUN.nestedContainers": "true" — enable nested container support (kind-style)
	//   "RUN.network":        "podman" — explicit network for rootless podman
	ExtraConfig map[string]string
}

// ContainerImageRegistry maps VM config attributes to OCI container images.
// It is embedded in the Registry and consulted during PowerOn to inject
// RUN.container into VMs that would otherwise start without container backing.
type ContainerImageRegistry struct {
	mu      sync.RWMutex
	entries []ContainerImageEntry
}

// Register appends an entry to the registry. Entries are matched in order.
func (r *ContainerImageRegistry) Register(e ContainerImageEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
}

// resolve returns a copy of the first entry that matches the given VM, or a
// zero-value entry if no match is found. Check OCIImage != "" to detect a match.
// The caller holds no VM lock; the VM's Config fields are read under the
// registry's own read-lock only.
func (r *ContainerImageRegistry) resolve(vm *VirtualMachine) ContainerImageEntry {
	if r == nil {
		return ContainerImageEntry{}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, e := range r.entries {
		if e.VMNameGlob != "" {
			if matched, _ := path.Match(e.VMNameGlob, vm.Config.Name); matched {
				return e
			}
		}

		if e.DiskPathGlob != "" {
			for _, dev := range vm.Config.Hardware.Device {
				disk, ok := dev.(*types.VirtualDisk)
				if !ok {
					continue
				}
				backing, ok := disk.Backing.(*types.VirtualDiskFlatVer2BackingInfo)
				if !ok {
					continue
				}
				if matched, _ := path.Match(e.DiskPathGlob, backing.FileName); matched {
					return e
				}
			}
		}
	}

	return ContainerImageEntry{}
}
