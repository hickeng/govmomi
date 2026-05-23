// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package simulator

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// VMCIPortHandler is a function that handles one vsock connection from the
// container to the host.  hostFd is the host end of the injected unix
// socketpair; the handler owns hostFd and must close it when done.
//
// The handler is called in its own goroutine.  It receives the port number
// the guest connected to, the CID it connected to, and the VM UID for
// logging purposes.
type VMCIPortHandler func(vmUID string, hostFd int, cid, port uint32)

// vmciPortRegistry routes AF_VSOCK connect() calls to registered handlers by port.
// Connections to unregistered ports fall through to the default handler (if set)
// or are bridged to the GuestRPC unix socket server (legacy behaviour).
type vmciPortRegistry struct {
	mu       sync.RWMutex
	handlers map[uint32]VMCIPortHandler
	dflt     VMCIPortHandler // fallback for unregistered ports; may be nil
}

func newVMCIPortRegistry() *vmciPortRegistry {
	return &vmciPortRegistry{handlers: make(map[uint32]VMCIPortHandler)}
}

// register installs handler for port.  Thread-safe.  Replaces any prior
// registration for the same port.
func (r *vmciPortRegistry) register(port uint32, h VMCIPortHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[port] = h
}

// setDefault installs a fallback handler invoked when no port-specific
// registration exists.
func (r *vmciPortRegistry) setDefault(h VMCIPortHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dflt = h
}

// lookup returns the handler for port, using the default if no port-specific
// handler is registered.  Returns nil if no handler is available.
func (r *vmciPortRegistry) lookup(port uint32) VMCIPortHandler {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if h, ok := r.handlers[port]; ok {
		return h
	}
	return r.dflt
}

// vsockWriteFilterFile writes the seccomp filter JSON for this VM to a temp
// file and returns the path.  It does NOT create the listenerPath socket or
// start the goroutine — call vsockStartListener just before "docker start" so
// the listener exists when crun/runc connects.
//
// Returns "" on any error (non-fatal: seccomp interception disabled).
func vsockWriteFilterFile(vmUID string) string {
	listenerSockPath := vsockInterceptListenerPath(vmUID)

	filter := seccompFilter{
		DefaultAction: "SCMP_ACT_ALLOW",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"},
		ListenerPath:  listenerSockPath,
		Syscalls: []seccompSyscall{
			{
				Names:  []string{"socket"},
				Action: "SCMP_ACT_NOTIFY",
				Args: []seccompArg{
					// arg[0] == AF_VSOCK (40)
					{Index: 0, Value: 40, Op: "SCMP_CMP_EQ"},
				},
			},
			{
				Names:  []string{"bind"},
				Action: "SCMP_ACT_NOTIFY",
				// No arg filter: intercept all bind() calls.
				// handleBind checks whether the FD is a tracked vsock socket;
				// non-vsock FDs receive SECCOMP_USER_NOTIF_FLAG_CONTINUE so the
				// kernel executes them normally.
				//
				// This is required because SocketConnectVmciInternal (simpleSocket.c)
				// calls bind(fd, AF_VSOCK_sockaddr) with a privileged source port
				// before calling connect().  The injected unix socket FD would get
				// EINVAL from the kernel for an AF_VSOCK sockaddr, causing vsock
				// channel startup to abort before connect() is ever called.
			},
			{
				Names:  []string{"connect"},
				Action: "SCMP_ACT_NOTIFY",
				// No arg filter: intercept all connect() calls; non-vsock FDs
				// receive SECCOMP_USER_NOTIF_FLAG_CONTINUE in the handler.
			},
		},
	}

	data, err := json.Marshal(filter)
	if err != nil {
		log.Printf("vsockWriteFilterFile: marshal: %v", err)
		return ""
	}

	f, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("vcsim-vsock-filter-%s-*.json", vmUID))
	if err != nil {
		log.Printf("vsockWriteFilterFile: create temp: %v", err)
		return ""
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		log.Printf("vsockWriteFilterFile: write: %v", err)
		_ = os.Remove(f.Name())
		return ""
	}

	return f.Name()
}

// newVsockInterceptAndStart creates a vsockIntercept for the given VM, binds
// the listenerPath socket synchronously, and launches the serve goroutine.
// It must be called after vsockWriteFilterFile (so the filter JSON already
// names the socket path) and immediately before "docker start".
//
// The socket is bound before this function returns, so crun can connect as
// soon as docker start runs — no race between goroutine scheduling and crun.
//
// Returns nil and logs on any error (non-fatal: seccomp interception disabled,
// GuestRPC server Component A still works via bind-mounted unix socket).
func newVsockInterceptAndStart(vmUID, guestRPCSocketPath, filterPath string) *vsockIntercept {
	listenerSockPath := vsockInterceptListenerPath(vmUID)

	_ = os.Remove(listenerSockPath)
	ln, err := net.Listen("unix", listenerSockPath)
	if err != nil {
		log.Printf("vsockIntercept %s: listen: %v", vmUID, err)
		return nil
	}
	log.Printf("vsockIntercept %s: listening at %s (filter: %s)", vmUID, listenerSockPath, filterPath)

	vi := newVsockIntercept(vmUID, listenerSockPath, guestRPCSocketPath, filterPath)
	vi.ln = ln

	// Register the built-in GuestRPC handler for port 976 (RPCI/GuestRPC channel).
	// Tests may override this or register additional port handlers via vi.reg.register().
	vi.reg.register(976, func(vmUID string, hostFd int, cid, port uint32) {
		vi.bridgeToGuestRPC(hostFd)
	})

	// wg.Add BEFORE go: ensures Stop()'s wg.Wait() is correct even if Stop()
	// is called before the goroutine has been scheduled by the runtime.
	vi.wg.Add(1)
	go func() {
		defer vi.wg.Done()
		vi.serve()
	}()

	return vi
}

// vsockInterceptListenerPath returns the path of the per-VM unix socket that
// runc connects to to hand off the seccomp master FD.
func vsockInterceptListenerPath(vmUID string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("vcsim-vsock-%s.sock", vmUID))
}

// seccompFilter is the JSON structure written to the seccomp profile temp file.
// It follows the OCI Runtime Spec 1.1.0 seccomp configuration schema.
type seccompFilter struct {
	DefaultAction string           `json:"defaultAction"`
	Architectures []string         `json:"architectures"`
	ListenerPath  string           `json:"listenerPath"`
	Syscalls      []seccompSyscall `json:"syscalls"`
}

type seccompSyscall struct {
	Names  []string     `json:"names"`
	Action string       `json:"action"`
	Args   []seccompArg `json:"args,omitempty"`
}

type seccompArg struct {
	Index uint   `json:"index"`
	Value uint64 `json:"value"`
	Op    string `json:"op"`
}

// vsockIntercept manages the seccomp notification event loop for one VM.
// It owns the listenerPath unix socket for the entire VM lifetime.
//
// Phase 6a (multi-accept design):
//
//	serve() loops on Accept() — one serveCrunConn goroutine per accepted
//	connection.  This allows podman exec (and any other operation that causes
//	crun to establish a second connection to listenerPath) to succeed: crun
//	gets a new seccompFd for its new process scope, and the existing event
//	loop continues handling the original container processes.
//
// Lifecycle:
//  1. newVsockInterceptAndStart() binds the socket (synchronously) and
//     launches serve().  The socket is in the kernel's listen state before
//     the function returns, so crun can connect the moment docker start runs.
//  2. serve() (in a goroutine) loops on Accept() with NO timeout.  Each
//     accepted connection spawns a serveCrunConn goroutine.  serve() exits
//     when ln is closed by Stop().
//  3. Each serveCrunConn goroutine receives the seccompFd from crun, stores
//     it in vi.seccompFds, then runs eventLoop.  The FD is removed from
//     vi.seccompFds when serveCrunConn exits.
//  4. Stop() closes vi.ln (unblocks serve()'s Accept()), closes all active
//     seccompFds (unblocks any blocked NOTIF_RECV), and calls wg.Wait() so
//     the caller knows all goroutines have fully exited.
type vsockIntercept struct {
	vmUID            string
	listenerSockPath string
	guestRPCSockPath string // used by port-976 bridge (legacy; new code uses reg)
	filterFilePath   string

	reg *vmciPortRegistry // per-port handler dispatch table

	// ready is closed the first time a seccompFd is successfully received,
	// providing a reliable signal that AF_VSOCK interception is active.
	// Tests wait on this before registering port handlers or exec-ing binaries.
	ready     chan struct{}
	readyOnce sync.Once

	ln      net.Listener // owned by this struct; closed by Stop()
	stopped bool         // set by Stop() before closing ln
	stopMu  sync.Mutex

	// Active seccompFds: closed by Stop() to unblock blocked NOTIF_RECV calls.
	// Each serveCrunConn goroutine adds its fd on start, removes on exit.
	seccompFds   map[int]struct{}
	seccompFdsMu sync.Mutex

	wg sync.WaitGroup

	// FD tracking: (PID, guestFD) → socketpair host-end FD.
	// Shared across all event loops for this VM.
	mu         sync.Mutex
	tracked    map[pidFDKey]int
	notifCount int // total seccomp notifications received (diagnostic only)
}

type pidFDKey struct {
	pid uint32
	fd  uint64
}

func newVsockIntercept(vmUID, listenerPath, guestRPCSockPath, filterPath string) *vsockIntercept {
	return &vsockIntercept{
		vmUID:            vmUID,
		listenerSockPath: listenerPath,
		guestRPCSockPath: guestRPCSockPath,
		filterFilePath:   filterPath,
		reg:              newVMCIPortRegistry(),
		ready:            make(chan struct{}),
		seccompFds:       make(map[int]struct{}),
		tracked:          make(map[pidFDKey]int),
	}
}

// Stop shuts down all goroutines and cleans up resources.
//
// It first marks the intercept as stopped, then closes the unix listener
// (which unblocks serve()'s Accept() call), then closes all active seccomp
// FDs (which unblocks any blocked NOTIF_RECV ioctl in the event loops), then
// waits for all goroutines to exit.
//
// Callers should ensure the container has been stopped before calling Stop()
// (svm.c.stop before svm.vsockVI.Stop) so the container exit also unblocks
// NOTIF_RECV — this is the belt-and-suspenders approach.
func (vi *vsockIntercept) Stop() {
	vi.stopMu.Lock()
	vi.stopped = true
	vi.stopMu.Unlock()

	// Close the listener to unblock serve()'s Accept() loop.
	_ = vi.ln.Close()

	// Close all active seccompFds to unblock any blocked NOTIF_RECV ioctls.
	vi.seccompFdsMu.Lock()
	for fd := range vi.seccompFds {
		_ = syscall.Close(fd)
	}
	vi.seccompFds = make(map[int]struct{})
	vi.seccompFdsMu.Unlock()

	// Wait for all serve/serveCrunConn/eventLoop goroutines to exit.
	//
	// Belt-and-suspenders timeout: SECCOMP_IOCTL_NOTIF_RECV is a blocking
	// ioctl that holds a kernel file-object reference.  Closing the seccompFd
	// via syscall.Close() above does NOT interrupt the ioctl (the fd close
	// removes the fd-table entry, but the ioctl continues on the underlying
	// file object).  The ioctl only unblocks when all supervised processes in
	// the container exit.
	//
	// Callers must stop the container before calling Stop() (see simVM.remove).
	// If that was done, event loops exit within milliseconds.  If not (e.g.,
	// called directly in tests or during a crash path), we timeout after 15 s
	// rather than blocking indefinitely — the goroutines will clean themselves
	// up when the container is eventually stopped/removed.
	done := make(chan struct{})
	go func() {
		vi.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		log.Printf("vsockIntercept %s: Stop: goroutines still running after 15 s "+
			"(container not stopped?); they will exit when the container exits",
			vi.vmUID)
	}
}

// serve is the listener goroutine.  It loops on Accept(), spawning one
// serveCrunConn goroutine per accepted crun connection.  This allows both
// the initial container start and subsequent podman exec invocations to
// each get their own seccomp event loop.
//
// serve exits when vi.ln is closed by Stop().
func (vi *vsockIntercept) serve() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("vsockIntercept %s: serve panic: %v\n%s", vi.vmUID, r, debug.Stack())
		}
		_ = vi.ln.Close()
		_ = os.Remove(vi.listenerSockPath)
		_ = os.Remove(vi.filterFilePath)
	}()

	for {
		conn, err := vi.ln.Accept()
		if err != nil {
			// Normal shutdown path: Stop() closed vi.ln.
			return
		}
		log.Printf("vsockIntercept %s: crun connected to listenerPath", vi.vmUID)

		vi.wg.Add(1)
		go func(c net.Conn) {
			defer vi.wg.Done()
			vi.serveCrunConn(c)
		}(conn)
	}
}

// serveCrunConn receives the seccomp master FD from a single crun connection,
// then runs the event loop for that seccomp scope until the container or exec
// process tree exits.  Multiple serveCrunConn goroutines may run concurrently
// for the same VM (one per container-start + one per podman exec).
func (vi *vsockIntercept) serveCrunConn(conn net.Conn) {
	unixConn := conn.(*net.UnixConn)
	defer unixConn.Close()

	seccompFd, err := vi.receiveFD(unixConn)
	if err != nil {
		log.Printf("vsockIntercept %s: receiveFD: %v", vi.vmUID, err)
		return
	}
	log.Printf("vsockIntercept %s: seccompFd received=%d; event loop starting", vi.vmUID, seccompFd)

	// Check whether Stop() was called before we received the FD.
	vi.stopMu.Lock()
	if vi.stopped {
		vi.stopMu.Unlock()
		_ = syscall.Close(seccompFd)
		return
	}
	vi.stopMu.Unlock()

	// Register seccompFd so Stop() can close it to unblock NOTIF_RECV.
	vi.seccompFdsMu.Lock()
	vi.seccompFds[seccompFd] = struct{}{}
	vi.seccompFdsMu.Unlock()

	// Signal once that the intercept is live.  Tests and external callers may
	// block on vi.ready before registering port handlers or exec-ing binaries.
	vi.readyOnce.Do(func() { close(vi.ready) })

	defer func() {
		vi.seccompFdsMu.Lock()
		if _, ok := vi.seccompFds[seccompFd]; ok {
			_ = syscall.Close(seccompFd)
			delete(vi.seccompFds, seccompFd)
		}
		vi.seccompFdsMu.Unlock()

		vi.mu.Lock()
		totalNotifs := vi.notifCount
		vi.mu.Unlock()
		log.Printf("vsockIntercept %s: eventLoop done (fd=%d); total notifications: %d",
			vi.vmUID, seccompFd, totalNotifs)
	}()

	if err := vi.eventLoop(seccompFd); err != nil {
		log.Printf("vsockIntercept %s: eventLoop: %v", vi.vmUID, err)
	}
}

// receiveFD reads the seccomp master FD sent by crun/runc via SCM_RIGHTS.
func (vi *vsockIntercept) receiveFD(conn *net.UnixConn) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4)) // 4 bytes for one int32 (the FD)
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, fmt.Errorf("ReadMsgUnix: %w", err)
	}

	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("ParseSocketControlMessage: %w", err)
	}
	for _, scm := range scms {
		fds, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}
	return -1, fmt.Errorf("no FD received via SCM_RIGHTS")
}

// ── Seccomp notification ioctl data structures ─────────────────────────────
// These structures and constants mirror the Linux kernel's seccomp_unotify(2)
// interface.  We define them manually because golang.org/x/sys/unix is not in
// the govmomi module graph.
//
// Sizes and ioctl numbers are for Linux amd64.  The IOWR encoding:
//   IOWR(type, nr, size) = (3<<30) | (size<<16) | (type<<8) | nr
//
// seccompNotif:      size=80  → 0xc050_2100
// seccompNotifResp:  size=24  → 0xc018_2101
// seccompNotifAddfd: size=24  → 0x4018_2103  (IOW, not IOWR)
//
// These values are stable across kernel versions for amd64.

const (
	sizeofSeccompNotif     = 80
	sizeofSeccompNotifResp = 24
	sizeofSeccompAddfd     = 24

	ioctlSeccompNotifRecv  = uintptr((3 << 30) | (sizeofSeccompNotif << 16) | (0x21 << 8) | 0)
	ioctlSeccompNotifSend  = uintptr((3 << 30) | (sizeofSeccompNotifResp << 16) | (0x21 << 8) | 1)
	ioctlSeccompNotifAddfd = uintptr((1 << 30) | (sizeofSeccompAddfd << 16) | (0x21 << 8) | 3)

	seccompUserNotifFlagContinue = uint32(0x1)
)

// seccompNotif mirrors struct seccomp_notif (include/uapi/linux/seccomp.h).
// We keep the layout explicit to avoid reflection overhead on the hot path.
type seccompNotif struct {
	ID    uint64
	PID   uint32
	Flags uint32
	Data  seccompData
}

// seccompData mirrors struct seccomp_data.
type seccompData struct {
	Nr                 int32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

// seccompNotifResp mirrors struct seccomp_notif_resp.
type seccompNotifResp struct {
	ID    uint64
	Val   int64
	Error int32
	Flags uint32
}

// seccompNotifAddfd mirrors struct seccomp_notif_addfd.
type seccompNotifAddfd struct {
	ID         uint64
	Flags      uint32
	SrcFd      uint32
	NewFd      uint32
	NewFdFlags uint32
}

// eventLoop processes seccomp notifications from seccompFd.
func (vi *vsockIntercept) eventLoop(seccompFd int) error {
	for {
		var notif seccompNotif
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(seccompFd), ioctlSeccompNotifRecv,
			uintptr(unsafe.Pointer(&notif))); errno != 0 {
			// ENOENT/ECANCELED: container exited normally.
			// EBADF: seccompFd closed (Stop() or container process tree gone).
			// EINTR: signal-interrupted; retry.
			if errno == syscall.EINTR {
				continue
			}
			if errno == syscall.ENOENT || errno == syscall.ECANCELED || errno == syscall.EBADF {
				return nil
			}
			return fmt.Errorf("SECCOMP_IOCTL_NOTIF_RECV: %w", errno)
		}

		vi.mu.Lock()
		vi.notifCount++
		count := vi.notifCount
		vi.mu.Unlock()

		switch notif.Data.Nr {
		case int32(syscall.SYS_SOCKET):
			log.Printf("vsockIntercept %s: RECV socket(AF_VSOCK) #%d pid=%d args=%v",
				vi.vmUID, count, notif.PID, notif.Data.Args[:3])
			go vi.handleSocket(seccompFd, &notif)
		case int32(syscall.SYS_BIND):
			// Fast path: skip goroutine for the common non-vsock case.
			// bind() is intercepted without argument filtering; nearly every
			// process in the container (kubelet, etcd, kube-apiserver) calls
			// bind() for TCP/UDP.  Only vsock FDs (previously injected via
			// handleSocket) are in vi.tracked; all others get CONTINUE
			// immediately in the event loop without spawning a goroutine.
			fd := notif.Data.Args[0]
			tgid := tidToTGID(notif.PID)
			vi.mu.Lock()
			_, vsockBind := vi.tracked[pidFDKey{pid: tgid, fd: fd}]
			vi.mu.Unlock()
			if !vsockBind {
				vi.respond(seccompFd, notif.ID, 0, 0, seccompUserNotifFlagContinue)
				continue
			}
			go vi.handleBind(seccompFd, &notif)
		case int32(syscall.SYS_CONNECT):
			// Fast path: same rationale as SYS_BIND above — avoid goroutine
			// spawn and logging for the vast majority of non-vsock connect()
			// calls that Kubernetes components make.
			fd := notif.Data.Args[0]
			tgid := tidToTGID(notif.PID)
			vi.mu.Lock()
			_, vsockConnect := vi.tracked[pidFDKey{pid: tgid, fd: fd}]
			vi.mu.Unlock()
			if !vsockConnect {
				vi.respond(seccompFd, notif.ID, 0, 0, seccompUserNotifFlagContinue)
				continue
			}
			log.Printf("vsockIntercept %s: RECV connect tracked #%d pid=%d fd=%d",
				vi.vmUID, count, notif.PID, fd)
			go vi.handleConnect(seccompFd, &notif)
		default:
			log.Printf("vsockIntercept %s: RECV unknown nr=%d #%d pid=%d",
				vi.vmUID, notif.Data.Nr, count, notif.PID)
			vi.respond(seccompFd, notif.ID, 0, 0, seccompUserNotifFlagContinue)
		}
	}
}

// handleSocket intercepts socket(AF_VSOCK, type, protocol).
// Creates a unix socketpair, injects one end into the container, records the mapping.
func (vi *vsockIntercept) handleSocket(seccompFd int, notif *seccompNotif) {
	sockType := int(notif.Data.Args[1]) // SOCK_STREAM=1, SOCK_DGRAM=2, etc.
	proto := int(notif.Data.Args[2])

	// Create the socketpair on the host.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, sockType|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		log.Printf("vsockIntercept: Socketpair: %v", err)
		vi.respond(seccompFd, notif.ID, 0, int32(syscall.ENOSYS), 0)
		return
	}
	hostFd, guestFd := fds[0], fds[1]
	defer syscall.Close(guestFd) // closed after ADDFD; kernel has dup'd it

	// Inject guestFd into the target container process.
	// Flags=0: allocate the lowest available FD; return value = allocated FD number.
	addfd := seccompNotifAddfd{
		ID:    notif.ID,
		Flags: 0, // IMPORTANT: 0 = allocate-lowest-FD (not SECCOMP_ADDFD_FLAG_SETFD)
		SrcFd: uint32(guestFd),
	}
	allocatedFD, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(seccompFd), ioctlSeccompNotifAddfd,
		uintptr(unsafe.Pointer(&addfd)))
	if errno != 0 {
		log.Printf("vsockIntercept: ADDFD: %v", errno)
		syscall.Close(hostFd)
		vi.respond(seccompFd, notif.ID, 0, int32(syscall.ENOSYS), 0)
		return
	}

	// Record the (TGID, allocatedFD) → hostFd mapping.
	// Use TGID (thread group ID = process PID) not TID: socket() and connect()
	// may be called by different threads in the same process; all threads share
	// the FD table so TGID+FD uniquely identifies the socket.
	tgid := tidToTGID(notif.PID)
	vi.mu.Lock()
	vi.tracked[pidFDKey{pid: tgid, fd: uint64(allocatedFD)}] = hostFd
	vi.mu.Unlock()

	log.Printf("vsockIntercept %s: socket(AF_VSOCK) tid=%d tgid=%d → allocatedFD=%d (hostFd=%d)",
		vi.vmUID, notif.PID, tgid, allocatedFD, hostFd)

	// Return the allocated FD number as the result of socket().
	vi.respond(seccompFd, notif.ID, int64(allocatedFD), 0, 0)
}

// handleBind intercepts bind() calls.
//
// vmtoolsd's SocketConnectVmciInternal (simpleSocket.c) calls:
//
//	bind(fd, &localAddr, sizeof localAddr)
//
// where localAddr is a struct sockaddr_vm with a privileged source port.
// The fd is our injected unix socketpair FD.  The kernel rejects an
// AF_VSOCK sockaddr on a unix socket (EINVAL), which causes vsock channel
// startup to abort before connect() is ever called.
//
// For tracked vsock FDs we return 0 (success) without kernel execution.
// All other bind() calls (TCP, plain unix, etc.) are passed to the kernel
// unchanged via FLAG_CONTINUE.
func (vi *vsockIntercept) handleBind(seccompFd int, notif *seccompNotif) {
	fd := notif.Data.Args[0]
	tgid := tidToTGID(notif.PID)

	vi.mu.Lock()
	_, ok := vi.tracked[pidFDKey{pid: tgid, fd: fd}]
	vi.mu.Unlock()

	if !ok {
		// Not a vsock FD we manage; let the kernel handle it normally.
		vi.respond(seccompFd, notif.ID, 0, 0, seccompUserNotifFlagContinue)
		return
	}

	log.Printf("vsockIntercept %s: bind fd=%d tgid=%d (tracked vsock socket) → returning success",
		vi.vmUID, fd, tgid)
	vi.respond(seccompFd, notif.ID, 0, 0, 0)
}

// handleConnect intercepts connect() calls.
//
// For tracked vsock FDs: routes to the registered VMCIPortHandler for the
// target port.  If no port-specific handler is registered and no default
// handler is set, falls back to bridgeToGuestRPC (legacy behaviour).
// For all other FDs: lets the kernel handle normally via FLAG_CONTINUE.
func (vi *vsockIntercept) handleConnect(seccompFd int, notif *seccompNotif) {
	fd := notif.Data.Args[0]

	// Use TGID to match the key written by handleSocket (same thread-group shares FDs).
	tgid := tidToTGID(notif.PID)

	vi.mu.Lock()
	hostFd, ok := vi.tracked[pidFDKey{pid: tgid, fd: fd}]
	if ok {
		// Remove the entry now: the handler goroutine takes ownership of hostFd,
		// and the (tgid, fd) pair becomes free for reuse once the container process
		// closes its end of the socketpair.
		delete(vi.tracked, pidFDKey{pid: tgid, fd: fd})
	}
	vi.mu.Unlock()

	if !ok {
		// Not a vsock FD we injected; let the kernel handle it.
		vi.respond(seccompFd, notif.ID, 0, 0, seccompUserNotifFlagContinue)
		return
	}
	log.Printf("vsockIntercept %s: connect tracked fd=%d tid=%d tgid=%d → hostFd=%d",
		vi.vmUID, fd, notif.PID, tgid, hostFd)

	// Read sockaddr_vm from the container process to extract CID and port.
	cid, port := vi.readSockaddrVM(notif.PID, notif.Data.Args[1], notif.Data.Args[2])
	log.Printf("vsockIntercept %s: connect pid=%d fd=%d cid=%d port=%d",
		vi.vmUID, notif.PID, fd, cid, port)

	// Dispatch to port handler.  The handler goroutine takes ownership of hostFd.
	handler := vi.reg.lookup(port)
	if handler != nil {
		go handler(vi.vmUID, hostFd, cid, port)
	} else {
		// No registered handler for this port: fallback to GuestRPC bridge.
		// This covers the case where newVsockInterceptAndStart is called without
		// registering a port-976 handler (e.g. in tests that construct vsockIntercept
		// directly with guestRPCSockPath set).
		log.Printf("vsockIntercept %s: no handler for port %d, falling back to GuestRPC bridge",
			vi.vmUID, port)
		go vi.bridgeToGuestRPC(hostFd)
	}

	// Return 0 (success): the socketpair is pre-connected; from the guest's
	// perspective the connect() completed successfully.
	vi.respond(seccompFd, notif.ID, 0, 0, 0)
}

// bridgeToGuestRPC connects hostFd (host end of a socketpair injected into
// the container) to the per-VM GuestRPC unix socket server by proxying bytes
// bidirectionally.
//
// hostFd must be an AF_UNIX socketpair FD.  It is wrapped as a net.Conn via
// net.FileConn so that Go's netpoller (epoll) manages it — using os.NewFile
// directly produces a blocking *os.File whose Read/Write calls pin OS threads
// and whose splice/sendfile optimisations degrade to no-ops for socket→socket
// copies, causing io.Copy to return immediately with 0 bytes.
func (vi *vsockIntercept) bridgeToGuestRPC(hostFd int) {
	// net.FileConn dups hostFd; we close the original so there is no leak.
	// The dup'd FD is now owned by hostConn and will be closed by hostConn.Close().
	f := os.NewFile(uintptr(hostFd), "vsock-host-end")
	hostConn, err := net.FileConn(f)
	f.Close() // safe: net.FileConn has dup'd the FD
	if err != nil {
		log.Printf("vsockIntercept %s: FileConn: %v", vi.vmUID, err)
		return
	}
	defer hostConn.Close()

	grpcConn, err := net.Dial("unix", vi.guestRPCSockPath)
	if err != nil {
		log.Printf("vsockIntercept %s: bridgeToGuestRPC dial: %v", vi.vmUID, err)
		return
	}
	defer grpcConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := io.Copy(grpcConn, hostConn)
		log.Printf("vsockIntercept %s: bridge container→GuestRPC done: %d bytes, %v", vi.vmUID, n, err)
		// Propagate EOF to GuestRPC serveConn.  Without this, serveConn
		// blocks in ReadUnixFrame forever after the container process closes
		// its socketpair FD, which in turn blocks GuestRPCServer.Stop()
		// (it waits for serveConn's wg.Done()).
		if cw, ok := grpcConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, err := io.Copy(hostConn, grpcConn)
		log.Printf("vsockIntercept %s: bridge GuestRPC→container done: %d bytes, %v", vi.vmUID, n, err)
		// Propagate EOF back to the container (e.g. if GuestRPC server
		// closes the connection from its side).
		if cw, ok := hostConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// tidToTGID returns the Thread Group ID (TGID = "process PID") for the given
// thread ID by reading /proc/<tid>/status.  In seccomp notifications, notif.PID
// is the TID of the calling thread, not the TGID.  For multi-threaded processes,
// a socket created by thread A (TID=X) may have connect() called by thread B
// (TID=Y); both share the same FD table.  Using TGID as the key ensures we
// find the tracked entry regardless of which thread calls the syscall.
//
// Falls back to tid on any error (single-threaded process case).
func tidToTGID(tid uint32) uint32 {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return tid
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Tgid:") {
			tgid, err := strconv.ParseUint(strings.TrimSpace(line[5:]), 10, 32)
			if err == nil {
				return uint32(tgid)
			}
		}
	}
	return tid
}

// readSockaddrVM reads a sockaddr_vm from the container process's address space
// using /proc/<pid>/mem.  Returns (cid, port) or (0, 0) on error.
//
// sockaddr_vm layout (from <linux/vm_sockets.h>):
//
//	sa_family  uint16 (2 bytes)
//	svm_reserved uint16 (2 bytes)
//	svm_port    uint32 (4 bytes)  ← offset 4
//	svm_cid     uint32 (4 bytes)  ← offset 8
//	svm_zero    [4]byte
func (vi *vsockIntercept) readSockaddrVM(pid uint32, addr, length uint64) (cid, port uint32) {
	if length < 12 {
		return 0, 0
	}
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	buf := make([]byte, 12)
	if _, err := f.ReadAt(buf, int64(addr)); err != nil {
		return 0, 0
	}
	port = binary.LittleEndian.Uint32(buf[4:8])
	cid = binary.LittleEndian.Uint32(buf[8:12])
	return cid, port
}

// respond sends a seccomp notification response.
// ENOENT: notification ID is stale (process exited before we responded) — expected.
// EBADF:  seccompFd was closed by a concurrent container exit — expected.
// Both are silently ignored; any other error is logged.
func (vi *vsockIntercept) respond(seccompFd int, id uint64, val int64, errCode int32, flags uint32) {
	resp := seccompNotifResp{
		ID:    id,
		Val:   val,
		Error: errCode,
		Flags: flags,
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(seccompFd), ioctlSeccompNotifSend,
		uintptr(unsafe.Pointer(&resp))); errno != 0 {
		if errno != syscall.ENOENT && errno != syscall.EBADF {
			log.Printf("vsockIntercept %s: NOTIF_SEND: %v", vi.vmUID, errno)
		}
	}
}
