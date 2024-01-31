package interpose

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

type session struct {
}

// newClient constructs a client to connect to the interpose server, initiates that connection, and returns the desired
// behaviour:
// * pass-through - invoke the command as is and don't tamper with IO
// * remote - do not invoke local, use IO from remote
// !! * in-path - invoke the local, but relay IO via the server - this will not be done until we need it as it interfers with
//
//	the process hierarchy unless we switch to ptrace for a sidecar interpose. Both are too complex for speculative impl.
func newClient(ctx context.Context, target string, args []string, env []string, pwd string) (Style, *session, error) {
	hostname, err := os.Hostname()
	if err != nil {
		panic("could not retrieve hostname")
	}

	config := &ssh.ClientConfig{
		User: hostname,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// load the config
	bytes, err := os.ReadFile(interposeClientConfigPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic(fmt.Sprintf("failed to open client config file %s: %s", interposeClientConfigPath, err))
		}
	}

	remote := string(bytes)
	if len(remote) == 0 {
		// disabled - so pass-through
		return PASSTHROUGH, nil, nil
	}

	// create the SSH client from the mocked connection
	fmt.Printf("connecting to interpose server at %s\n", remote)
	// TODO: make the timeout part of the config file so the server can determine its own latency
	// config.Timeout = 3 * time.Second
	client, err := ssh.Dial("tcp", remote, config)
	if err != nil {
		// TODO: check if this is a timeout... also see if we can check if the server is being debugged as that would
		// cause a slow server response.
		panic(fmt.Sprintf("failed to open interpose connection to server: %s", err))
	}

	invocation := Invocation{
		Target: target,
		Args:   args,
		Pwd:    pwd,
	}

	chans, reqs, err := client.OpenChannel("interpose", invocation.Marshal())
	if err != nil {
		switch terr := err.(type) {
		case *ssh.OpenChannelError:
			err2 := client.Close()
			if err2 != nil {
				panic(err2)
			}

			if terr.Reason == ssh.Prohibited && terr.Message == string(PASSTHROUGH) {
				fmt.Printf("pass-through %s\n", target)
				return PASSTHROUGH, nil, nil
			}

			panic(terr)
		default:
			panic(fmt.Sprintf("filed to open interpose channel to server: %s", err))
		}
	}

	fmt.Printf("non pass-through %s\n", target)

	defer chans.Close()
	defer client.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for msg := range reqs {
			log.Printf("received request: %+v", msg)
		}
	}()

	wg.Done()

	return REMOTE, nil, nil
}

// ConstructContainerConfig takes a server address and returns:
// * a suitable interpose client config
// * a path at which interpose client will look for config
func ConstructContainerConfig(server netip.Addr, port int) (config string, path string) {
	config = fmt.Sprintf("%s:%d", server.String(), port)
	path = interposeClientConfigPath

	return
}
