package simulator

import (
	"log"
	"net"
	"net/netip"
	"sync"

	"github.com/vmware/govmomi/simulator/interpose"
)

// TODO: move this into vcsim instance or keep global?
var globalInterposeServer = &interposeServer{}

type interposeServer struct {
	sync.Mutex

	remotes map[string]*container
	server  *interpose.Server
}

func (is *interposeServer) registerContainerForInterpose(ctx *Context, c *container) {
	is.Lock()
	if is.remotes == nil {
		is.remotes = make(map[string]*container, 1)
	}

	_, registered := is.remotes[c.id]
	if !registered {
		if len(is.remotes) == 0 {
			// TODO: with podman you need to have a container running to have a bridge
			// interface present. Figure out a way to not fail catastrophically in this
			// scenario.
			is.start()
		}

		is.remotes[c.id] = c
	}
	is.Unlock()

	c.enableInterpose(ctx, is.addr(), is.port())
}

func (is *interposeServer) unregisterContainerForInterpose(ctx *Context, c *container) {
	is.Lock()
	c, registered := is.remotes[c.id]
	if !registered {
		is.Unlock()
		return
	}

	// conceptually we should be disabling interpose at this point as that prevents the client
	// trying to connect to a server on which it's no longer valid. However we don't want to
	// do a call out while under lock, and the server state manipulation should all occur under
	// the same lock, so we do it at the end instead.
	delete(is.remotes, c.id)

	if len(is.remotes) == 0 {
		is.stop()
	}
	is.Unlock()

	c.disableInterpose(ctx)
}

// start will attempt (and fail) to create a UDP connection to the IPv4 associated with the container runtime
// bridge. The source IP of this connection is therefore a suitable local IP for hosting a server to expose to
// containers.
// ?? for follow up -current testing shows it returning the bridge IP itself.. which is odd, but maybe not an issue.
func (is *interposeServer) start() error {
	serverAddr := netip.MustParseAddr("0.0.0.0")

	// Get preferred IP for talking to containers
	// this isn't just hardcoded to the bridge IP directly to allow a path for having a remote container host
	// at some point
	bridgeAddr, err := getBridgeAddr()
	if err == nil {
		conn, err := net.Dial("udp", netip.AddrPortFrom(bridgeAddr, 80).String())
		if err != nil {
			log.Printf("failed to initiate UDP client: %s", err)
		} else {
			localAddr := conn.LocalAddr().(*net.UDPAddr)
			conn.Close()

			addr, ok := netip.AddrFromSlice(localAddr.IP)
			if !ok {
				log.Println("failed to convert IP to netip")
			}

			serverAddr = addr.Unmap()
		}
	}

	is.server, _ = interpose.NewServer(serverAddr)
	return nil
}

func (is *interposeServer) addr() netip.Addr {
	if is.server == nil {
		return netip.Addr{}
	}

	return is.server.IP()
}

func (is *interposeServer) port() int {
	if is.server == nil {
		return 0
	}

	return is.server.Port()
}

func (is *interposeServer) stop() error {
	return nil
}

// enableInterpose configures interpose within the container. For this to be effective, the
// image has to have been prepped for interpose.
// TODO: check image metadata for interpose support
func (c *container) enableInterpose(ctx *Context, server netip.Addr, port int) error {
	config, path := interpose.ConstructContainerConfig(server, port)

	c.interpose = true

	err := writeFile(c.id, path, []byte(config))
	log.Printf("enable interpose on %s: %s", c.id, err)

	return err
}

func (c *container) disableInterpose(ctx *Context) error {
	_, path := interpose.ConstructContainerConfig(netip.Addr{}, 0)

	c.interpose = false

	err := writeFile(c.id, path, []byte{})
	log.Printf("disable interpose on %s: %s", c.id, err)

	return err
}
