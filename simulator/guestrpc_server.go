// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

package simulator

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/vmware/govmomi/toolbox"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	// GuestRPCSocketName is the well-known path inside every container-backed VM
	// with RUN.vmci=true. The host-side unix socket is bind-mounted to this path.
	GuestRPCSocketName = "/run/vmware/rpc.sock"
)

// GuestRPCServer is a per-VM host-side server that implements the toolbox RPCI
// protocol over a Unix stream socket.
//
// Wire format: 4-byte LE uint32 length prefix + payload bytes, matching
// toolbox.WriteUnixFrame / toolbox.ReadUnixFrame. Response status prefix:
// "1 " = success, "0 " = error (same as toolbox.rpciOK / rpciERR).
//
// Each VM with RUN.vmci=true has its own GuestRPCServer at a unique socket path.
// Multiple concurrent VMs do not share any state.
//
// Lifecycle:
//
//	srv = newGuestRPCServer(vm, path)
//	srv.Start(ctx)    — before container create; removes stale socket from prior crash
//	(container runs; guest code connects and issues RPCI commands)
//	srv.Stop()        — from simVM.stop() / simVM.remove()
//
// Recovery: Start removes any stale socket file before binding, so a crashed test
// does not block the next run. The socket file is also removed by Stop().
type GuestRPCServer struct {
	vm         *VirtualMachine
	ctx        *Context // captures the PowerOn Context for AutoUpdate
	socketPath string   // host-side absolute path

	ln   net.Listener
	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	// rpcMu serializes concurrent infoGet / infoSet calls from multiple
	// serveConn goroutines.  Without this, concurrent goroutines sharing the
	// same s.ctx bypass ObjectLock's mutual exclusion (ObjectLock.Acquire
	// grants re-entry to the same *Context pointer, so all serveConn goroutines
	// that share s.ctx can enter WithLock/AutoUpdate simultaneously, causing a
	// data race on ExtraConfig).
	//
	// Lock order: rpcMu → ObjectLock (via WithLock/AutoUpdate).  This order is
	// consistent because no code holds ObjectLock and then acquires rpcMu.
	rpcMu sync.RWMutex
}

// newGuestRPCServer creates (but does not start) a GuestRPCServer.
func newGuestRPCServer(vm *VirtualMachine, socketPath string) *GuestRPCServer {
	return &GuestRPCServer{
		vm:         vm,
		socketPath: socketPath,
		done:       make(chan struct{}),
	}
}

// GuestRPCSocketPath returns the canonical per-VM host-side unix socket path.
// Keyed on the VM UUID so concurrent VMs never share a path.
func GuestRPCSocketPath(vmUID string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("vcsim-rpc-%s.sock", vmUID))
}

// Start begins listening on the unix socket and launches the accept loop.
// ctx is the PowerOn/start Context; it is stored and used for AutoUpdate calls.
// Removes any stale socket file from a prior crash before binding.
func (s *GuestRPCServer) Start(ctx *Context) error {
	s.ctx = ctx

	// Remove stale socket from a prior crash.  If a live process still holds
	// the socket, net.Listen will fail — surfacing the conflict rather than
	// silently breaking it.
	_ = os.Remove(s.socketPath)

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("GuestRPCServer %s: %w", s.vm.Name, err)
	}
	s.ln = ln

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop closes the listener, signals the accept loop to exit, waits for all
// handler goroutines to finish, and removes the socket file.
// Safe to call multiple times (idempotent via sync.Once).
func (s *GuestRPCServer) Stop() {
	s.once.Do(func() {
		close(s.done)
		if s.ln != nil {
			_ = s.ln.Close()
		}
	})
	s.wg.Wait()
	_ = os.Remove(s.socketPath)
}

func (s *GuestRPCServer) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return // normal shutdown; listener was closed by Stop()
			default:
				log.Printf("GuestRPCServer %s: accept: %v", s.vm.Name, err)
				return
			}
		}
		log.Printf("GuestRPCServer %s: new connection from %s", s.vm.Name, conn.RemoteAddr())
		s.wg.Add(1)
		go s.serveConn(conn)
	}
}

func (s *GuestRPCServer) serveConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("GuestRPCServer %s: panic in serveConn: %v\n%s",
				s.vm.Name, r, debug.Stack())
		}
	}()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		msg, err := toolbox.ReadUnixFrame(conn)
		if err != nil {
			return // EOF or peer closed
		}
		if msg == nil {
			// Zero-length frame: heartbeat / empty poll.  Acknowledge with "1 ".
			if werr := toolbox.WriteUnixFrame(conn, []byte("1 ")); werr != nil {
				return
			}
			continue
		}

		rpcCmd := strings.TrimRight(string(msg), "\x00")
		log.Printf("GuestRPCServer %s: cmd=%q", s.vm.Name, rpcCmd)
		resp := s.dispatch(rpcCmd)
		if werr := toolbox.WriteUnixFrame(conn, []byte(resp)); werr != nil {
			return
		}
	}
}

// dispatch parses and executes an RPCI command.
func (s *GuestRPCServer) dispatch(cmd string) string {
	switch {
	case strings.HasPrefix(cmd, "info-get "):
		return s.infoGet(strings.TrimPrefix(cmd, "info-get "))

	case strings.HasPrefix(cmd, "info-set "):
		rest := strings.TrimPrefix(cmd, "info-set ")
		// "info-set guestinfo.key value with spaces"
		parts := strings.SplitN(rest, " ", 2)
		if len(parts) == 2 {
			return s.infoSet(parts[0], parts[1])
		}
		return "0 Bad syntax for info-set"

	case strings.HasPrefix(cmd, "tools.capability."),
		strings.HasPrefix(cmd, "tools.set-state"),
		strings.HasPrefix(cmd, "tools.set.version"),
		strings.HasPrefix(cmd, "Capabilities_Register"):
		// Acknowledge without semantic effect.
		return "1 "

	default:
		return "0 Unknown command"
	}
}

// infoGet reads key from the VM's ExtraConfig under the object lock.
func (s *GuestRPCServer) infoGet(key string) string {
	s.rpcMu.RLock()
	defer s.rpcMu.RUnlock()

	var result string
	found := false

	s.ctx.WithLock(s.vm, func() {
		for _, opt := range s.vm.Config.ExtraConfig {
			v := opt.GetOptionValue()
			if v.Key == key {
				if v.Value != nil {
					result = fmt.Sprintf("%v", v.Value)
				}
				found = true
				break
			}
		}
	})

	if found {
		return "1 " + result
	}
	return "0 No value found"
}

// infoSet writes key=value to the VM's ExtraConfig and emits a PropertyChange.
func (s *GuestRPCServer) infoSet(key, value string) string {
	s.rpcMu.Lock()
	defer s.rpcMu.Unlock()

	log.Printf("GuestRPCServer %s: info-set %s=%q", s.vm.Name, key, value)
	s.ctx.AutoUpdate(s.vm, func() {
		for _, opt := range s.vm.Config.ExtraConfig {
			v := opt.GetOptionValue()
			if v.Key == key {
				v.Value = value
				return
			}
		}
		s.vm.Config.ExtraConfig = append(s.vm.Config.ExtraConfig,
			&types.OptionValue{Key: key, Value: value})
	})
	return "1 "
}

// vmciEnabled reports whether the full VMCI simulation layer (Component A:
// GuestRPC unix socket server + Component B: seccomp AF_VSOCK intercept) should
// be activated for this VM.  Returns true when RUN.vmci is set to "true"
// (case-insensitive, whitespace-trimmed) in extraConfig.
func vmciEnabled(extraConfig []types.BaseOptionValue) bool {
	for _, opt := range extraConfig {
		v := opt.GetOptionValue()
		if v.Key != "RUN.vmci" {
			continue
		}
		s, ok := v.Value.(string)
		return ok && strings.EqualFold(strings.TrimSpace(s), "true")
	}
	return false
}

// guestRPCVolumeMount returns the -v argument for bind-mounting the per-VM
// GuestRPC socket into the container.
func guestRPCVolumeMount(socketPath string) string {
	return fmt.Sprintf("%s:%s", socketPath, GuestRPCSocketName)
}
