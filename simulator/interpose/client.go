/*
Copyright (c) 2024-2024 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package interpose

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"

	"golang.org/x/crypto/ssh"
)

const configCtxKey = "interpose-client-config"

// TODO: turn this into an interface or base type so that we can return static mocks as well as interactive streams
type result interface {
	stdout() *bytes.Reader
	stderr() *bytes.Reader
	exitCode() uint8
}

func (s *Static) stdout() *bytes.Reader {
	return bytes.NewReader(s.Stdout)
}

func (s *Static) stderr() *bytes.Reader {
	return bytes.NewReader(s.Stderr)
}

func (s *Static) exitCode() uint8 {
	return s.ExitCode
}

func (r *Remote) stdout() *bytes.Reader {
	panic("unimplemented")
}

func (r *Remote) stderr() *bytes.Reader {
	panic("unimplemented")
}

func (r *Remote) exitCode() uint8 {
	panic("unimplemented")
}

// newClient constructs a client to connect to the interpose server, initiates that connection, and returns the desired
// behaviour:
// * pass-through - invoke the command as is and don't tamper with IO
// * static-mock - do not invoke the, use IO from remote in the form of byte arrays for stdout/err
// * remote - do not invoke local, use IO streams from remote
// !! * in-path - invoke the local, but relay IO via the server - this will not be done until we need it as it interfers with
//
//	the process hierarchy unless we switch to ptrace for a sidecar interpose. Both are too complex for speculative impl.
func newClient(ctx context.Context, target string, args []string, env []string, pwd string) (Style, result, error) {
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
	bytes := ctx.Value(configCtxKey).([]byte)
	remote := string(bytes)
	if len(remote) == 0 {
		// disabled - so pass-through
		return PASSTHROUGH, nil, nil
	}

	// create the SSH client from the mocked connection
	console("connecting to interpose server at %s", remote)
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
		Env:    env,
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
				console("pass-through %s", target)
				return PASSTHROUGH, nil, nil
			}

			panic(terr)
		default:
			panic(fmt.Sprintf("filed to open interpose channel to server: %s", err))
		}
	}

	console("non pass-through %s", target)

	defer chans.Close()
	defer client.Close()

	var style Style
	var result result
	var retErr error
	for msg := range reqs {
		console("received request: %+v", msg)

		if msg == nil {
			panic("nil request on interpose connection")
		}

		var err error
		switch msg.Type {
		case string(PASSTHROUGH):
			// we don't care about payload for pass-through
			style = PASSTHROUGH

		case string(STATIC):
			res := &Static{}
			result = res
			err = res.Unmarshal(msg.Payload)

			// !! add debug loggin to see why res is returning as nil

			// TODO: return a static "session" for interpose to process
			style = STATIC

		case string(REMOTE):
			res := &Remote{}
			result = res
			err = res.Unmarshal(msg.Payload)

			// TODO: return a dynamic session for interpose to process

			// TODO: wrap reqs as they must be processed.
			panic("unimplemented")

		default:
			panic("unrecognized request type")
		}

		if msg.WantReply {
			msg.Reply(err == nil, nil)
		}

		if err != nil {
			console("error unmarshalling interpose handling details: %s", err)
			panic(err)
		}
	}

	return style, result, retErr
}

// ConstructContainerConfig takes a server address and returns:
// * a suitable interpose client config
// * a path at which interpose client will look for config
func ConstructContainerConfig(server netip.Addr, port int) (config string, path string) {
	config = fmt.Sprintf("%s:%d", server.String(), port)
	path = interposeClientConfigPath

	return
}
