// © Broadcom. All Rights Reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
// SPDX-License-Identifier: Apache-2.0

package simulator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

	// Peek at the first 4 bytes to detect the framing protocol in use.
	//
	// Two protocols reach this server:
	//
	//  1. DataMap / vsock protocol — used by real vmtoolsd binaries.
	//     The first 4 bytes are a big-endian uint32 = length of the DataMap
	//     entries section.  For realistic payloads this value is 10–500 bytes,
	//     so the first byte is 0x00.  Interpreted as little-endian the value
	//     is enormous (> 1 GB), which is the distinguishing property.
	//
	//  2. LE-frame protocol — used by the vmci-guest test binary and
	//     toolbox.UnixChannel.  The first 4 bytes are a little-endian uint32 =
	//     payload length.  For realistic payloads this value is 10–500 bytes,
	//     so the last byte is 0x00.  Interpreted as big-endian the value is
	//     enormous (> 1 GB).
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	beLen := binary.BigEndian.Uint32(hdr[:])
	leLen := binary.LittleEndian.Uint32(hdr[:])

	// MultiReader replays the header bytes so framing logic can re-read them.
	mr := io.MultiReader(bytes.NewReader(hdr[:]), conn)

	const maxReasonableLen = 1 << 20 // 1 MiB
	if beLen < maxReasonableLen && leLen >= maxReasonableLen {
		// DataMap framing: big-endian length prefix + DataMap-encoded body.
		s.serveConnDataMap(mr, conn)
	} else {
		// LE-frame framing: little-endian length prefix + raw payload.
		// Reads via mr (replays header), writes directly to conn.
		s.serveConnLEWithConn(mr, conn)
	}
}

// serveConnLEWithConn handles connections using the 4-byte LE length-prefix
// framing (toolbox.UnixChannel / vmci-guest test binary protocol).
func (s *GuestRPCServer) serveConnLEWithConn(r io.Reader, w io.Writer) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		msg, err := toolbox.ReadUnixFrame(r)
		if err != nil {
			return
		}
		if msg == nil {
			if werr := toolbox.WriteUnixFrame(w, []byte("1 ")); werr != nil {
				return
			}
			continue
		}
		rpcCmd := strings.TrimRight(string(msg), "\x00")
		log.Printf("GuestRPCServer %s: cmd=%q", s.vm.Name, rpcCmd)
		resp := s.dispatch(rpcCmd)
		if werr := toolbox.WriteUnixFrame(w, []byte(resp)); werr != nil {
			return
		}
	}
}

// serveConnDataMap handles connections using the DataMap framing protocol,
// which is the wire format used by real vmtoolsd binaries over vsock.
//
// Each message is encoded as:
//
//	[4-byte BE uint32: entries_length]
//	[entries: repeated { type(4B BE) fieldId(4B BE) value... }]
//
// Field types: DMFIELDTYPE_INT64=1, DMFIELDTYPE_STRING=2
// Field IDs:   GUESTRPCPKT_FIELD_TYPE=1, GUESTRPCPKT_FIELD_PAYLOAD=2,
//
//	GUESTRPCPKT_FIELD_FAST_CLOSE=3
//
// The RPC command is the FIELD_PAYLOAD string; the response is a DataMap
// with FIELD_TYPE=TYPE_DATA and FIELD_PAYLOAD="1 result" or "0 error".
func (s *GuestRPCServer) serveConnDataMap(r io.Reader, w io.Writer) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		payload, fastClose, err := readDataMapPacket(r)
		if err != nil {
			return // EOF or peer closed
		}

		rpcCmd := strings.TrimRight(string(payload), "\x00")
		log.Printf("GuestRPCServer %s: [vsock/DataMap] cmd=%q fastClose=%v",
			s.vm.Name, rpcCmd, fastClose)

		resp := s.dispatch(rpcCmd)
		if werr := writeDataMapPacket(w, []byte(resp)); werr != nil {
			return
		}

		if fastClose {
			// Client set FAST_CLOSE: it will close the connection after the
			// response; no need to loop.
			return
		}
	}
}

// readDataMapPacket reads one DataMap-framed packet from r and returns the
// FIELD_PAYLOAD string and the FAST_CLOSE flag.
func readDataMapPacket(r io.Reader) (payload []byte, fastClose bool, err error) {
	// Read 4-byte BE header = length of entries section.
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	entriesLen := binary.BigEndian.Uint32(hdr[:])
	if entriesLen == 0 {
		return nil, false, nil // empty / heartbeat
	}

	entries := make([]byte, entriesLen)
	if _, err = io.ReadFull(r, entries); err != nil {
		return
	}

	// Parse DataMap entries.
	buf := entries
	for len(buf) >= 8 {
		fieldType := binary.BigEndian.Uint32(buf[:4])
		fieldID := binary.BigEndian.Uint32(buf[4:8])
		buf = buf[8:]

		const (
			dmFieldTypeInt64  = 1
			dmFieldTypeString = 2
		)
		const (
			guestRPCFieldType      = 1
			guestRPCFieldPayload   = 2
			guestRPCFieldFastClose = 3
		)

		switch fieldType {
		case dmFieldTypeInt64:
			if len(buf) < 8 {
				err = fmt.Errorf("DataMap: truncated int64 field %d", fieldID)
				return
			}
			low := binary.BigEndian.Uint32(buf[:4])
			// high := binary.BigEndian.Uint32(buf[4:8]) // unused
			buf = buf[8:]
			if fieldID == guestRPCFieldFastClose && low != 0 {
				fastClose = true
			}
		case dmFieldTypeString:
			if len(buf) < 4 {
				err = fmt.Errorf("DataMap: truncated string length field %d", fieldID)
				return
			}
			strLen := binary.BigEndian.Uint32(buf[:4])
			buf = buf[4:]
			if uint32(len(buf)) < strLen {
				err = fmt.Errorf("DataMap: truncated string body field %d (want %d have %d)",
					fieldID, strLen, len(buf))
				return
			}
			s := buf[:strLen]
			buf = buf[strLen:]
			if fieldID == guestRPCFieldPayload {
				payload = s
			}
		default:
			// Unknown field type — stop parsing to avoid infinite loops on
			// malformed input.
			log.Printf("GuestRPCServer: unknown DataMap field type %d id %d, stopping parse",
				fieldType, fieldID)
			return
		}
	}
	return
}

// writeDataMapPacket encodes payload as a DataMap packet and writes it to w.
// The packet contains FIELD_TYPE=TYPE_DATA and FIELD_PAYLOAD=payload.
func writeDataMapPacket(w io.Writer, payload []byte) error {
	const (
		dmFieldTypeInt64  = 1
		dmFieldTypeString = 2

		guestRPCFieldType    = 1
		guestRPCFieldPayload = 2
		guestRPCTypeData     = 1
	)

	// Entry 1: FIELD_TYPE (int64 = TYPE_DATA = 1)
	//   type(4) + fieldId(4) + low32(4) + high32(4) = 16 bytes
	// Entry 2: FIELD_PAYLOAD (string = payload)
	//   type(4) + fieldId(4) + strlen(4) + bytes = 12 + len(payload) bytes
	entriesLen := 16 + 12 + len(payload)
	buf := make([]byte, 4+entriesLen)

	off := 0
	put32 := func(v uint32) {
		binary.BigEndian.PutUint32(buf[off:], v)
		off += 4
	}

	put32(uint32(entriesLen)) // header: entries length

	// FIELD_TYPE = TYPE_DATA (int64 = 1)
	put32(dmFieldTypeInt64)
	put32(guestRPCFieldType)
	put32(guestRPCTypeData) // low32
	put32(0)                // high32

	// FIELD_PAYLOAD = response string
	put32(dmFieldTypeString)
	put32(guestRPCFieldPayload)
	put32(uint32(len(payload)))
	copy(buf[off:], payload)

	_, err := w.Write(buf)
	return err
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
