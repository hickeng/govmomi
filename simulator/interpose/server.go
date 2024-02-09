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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/netip"

	"golang.org/x/crypto/ssh"
)

type Server struct {
	listener net.Listener

	cancelFunc context.CancelFunc
}

// pulled from https://github.com/vmware/vic/blob/master/cmd/tether/attach_test.go#L211C1-L226C2
func genKey() []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		panic("unable to generate private key")
	}

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}

	return pem.EncodeToMemory(&privateKeyBlock)
}

// NewServer
// An SSH server is represented by a ServerConfig, which holds certificate details and handles authentication of ServerConns.
// In the case of interpose we don't care about security in the slightest so we abuse this to avoid overhead.
func NewServer(addr netip.Addr, handlers *Handlers) (*Server, error) {

	ctx, cancelFunc := context.WithCancel(context.Background())
	server := &Server{
		cancelFunc: cancelFunc,
	}

	// pulled from https://github.com/vmware/vic/blob/9489f63e37c67fba813bb72f447338e6360b1d14/cmd/tether/attach.go#L212
	// where we also didn't need to care about credentials

	config := &ssh.ServerConfig{
		// expect the User to be an indentifier for the remote, eg. IP, MAC, moid, etc
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
		NoClientAuth: true,
	}

	// Need to have a key for the protocol even if we're sidestepping any sane auth above
	// TODO: confirm if this is still necessary
	pkey, err := ssh.ParsePrivateKey(genKey())
	if err != nil {
		panic(fmt.Sprintf("failed to load key for attach: %s", err))
	}

	config.AddHostKey(pkey)

	// Once a ServerConfig has been configured, connections can be accepted.
	// We let the system chose a suitable port
	server.listener, err = net.Listen("tcp", addr.String()+":0")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	// process incoming socket connections and pass them off for processing
	go func() {
		for ctx.Err() == nil {
			incoming, err := server.listener.Accept()
			if err != nil {
				log.Fatal("failed to accept incoming connection: ", err)
			}

			// Before use, a handshake must be performed on the incoming net.Conn.
			conn, chans, reqs, err := ssh.NewServerConn(incoming, config)
			if err != nil {
				log.Fatal("failed to handshake: ", err)
			}

			// The incoming Request channel must be serviced.
			go func() {
				ssh.DiscardRequests(reqs)
			}()

			go func() {
				// Service the incoming Channel channel.
				for newChannel := range chans {
					if newChannel.ChannelType() != "interpose" {
						log.Printf("unknown channel type from remote %s", conn.User())
						newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
						continue
					}

					data := newChannel.ExtraData()
					invocation := &Invocation{}
					err = invocation.Unmarshal(data)
					if err != nil {
						log.Printf("failed to unmarshal invocation details from remote: %s, %+v", conn.User(), err)
					}

					log.Printf("Invocation: extradata: %d, remote: %+v, target: %s, args: %+v, env: %+v", len(data), invocation.RuntimeIDs, invocation.Target, invocation.Args, invocation.Env)

					registered, id, msg := handlers.processInvocation(invocation)
					if registered {
						log.Printf("Processed by handler %+s", id)
					} else {
						log.Printf("Processed by fallback")
					}

					switch action := msg.(type) {
					case *PassThrough:
						err = newChannel.Reject(ssh.Prohibited, string(PASSTHROUGH))
						log.Printf("Pass-through")
						if err != nil {
							panic("Failed to direct remote to a pass-through invocation")
						}

					case *Static:
						chans, reqs, err := newChannel.Accept()
						if err != nil {
							log.Fatalf("error accepting channel for interpose request: %s", err)
						}

						_, err = chans.SendRequest(string(STATIC), false, action.Marshal())
						if err != nil {
							log.Fatalf("error from static interpose request: %s", err)
						}

						go ssh.DiscardRequests(reqs)
						chans.Close()

					case *Remote:
						panic("unimplemented")
					default:
						panic("unknown type of interpose response")
					}
				}
			}()
		}
	}()

	return server, nil
}

func (s *Server) Port() int {
	if s.listener == nil {
		return 0
	}

	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *Server) IP() netip.Addr {
	if s.listener == nil {
		return netip.Addr{}
	}

	addr, _ := netip.AddrFromSlice(s.listener.Addr().(*net.TCPAddr).IP)
	return addr
}
