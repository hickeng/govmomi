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

import "golang.org/x/crypto/ssh"

type Style string

const InvocationReq = "invocation"
const (
	PASSTHROUGH Style = "pass-through"
	STATIC      Style = "static-mock"
	REMOTE      Style = "remote"
)

// pulled from https://github.com/vmware/vic/blob/master/lib/tether/msgs/messages.go#L28C1-L59C2
type Message interface {
	// Returns the message name
	RequestType() string

	// Marshalled version of the message
	Marshal() []byte

	// Unmarshal unpacks the message
	Unmarshal([]byte) error
}

type Invocation struct {
	// TODO: add version for ssh marshal/unmarshal.

	// Runtime provides identifiers for the runtime environment the invocation is occuring in.
	// In practice this means a container in the simulator, but presenting a map of IDs allows
	// us to provide a mix of different domain identifiers, eg. moid, containerID, IP address,
	// MAC addresses, etc... all of which can be convenient for lookup in different contexts.
	RuntimeIDs []string

	// Target executable
	Target string
	Args   []string
	Env    []string
	// Pwd is included because it's critical context for commonly used calls and not necessarily present in Env
	Pwd string

	// User string
	// Groups []string

	// Pid uint
	// Pgid uint
}

func (i *Invocation) RequestType() string {
	return InvocationReq
}

func (i *Invocation) Marshal() []byte {
	return ssh.Marshal(i)
}

func (i *Invocation) Unmarshal(payload []byte) error {
	return ssh.Unmarshal(payload, i)
}

// Static is a response type for a non-interactive static mock, ie. it's just flat data returned rather than a
// stream interaction with the interpose server
// stdout and err are 2d arrays so that it's possible to package some degree of coordination in terms of when
// those bytes get written out, ie. stdout[0] will be written first, then stderr[0], then stdout[1], ....
// Members need to be exported for ssh package to Marshal/Unmarshal
// !! currently flattened to uint8 single dimensional array because of ssh marshalling.
type Static struct {
	Stdout   []uint8
	Stderr   []uint8
	ExitCode uint8
}

func (s *Static) RequestType() string {
	return string(STATIC)
}

func (s *Static) Marshal() []byte {
	return ssh.Marshal(s)
}

func (s *Static) Unmarshal(payload []byte) error {
	return ssh.Unmarshal(payload, s)
}

func (s *Static) SetOutput(stdout []byte, stderr []byte) *Static {
	if s == nil {
		return s
	}

	s.Stdout = stdout
	s.Stderr = stderr

	// !! currently flattened to uint8 single dimensional array because of ssh marshalling.
	// s.Stdout = append(s.Stdout, stdout)
	// s.Stderr = append(s.Stderr, stderr)

	return s
}

// Remote is a response type for a fully interactive mock, with I/O streams glued back to the testcase
type Remote struct {
}

func (r *Remote) RequestType() string {
	return string(REMOTE)
}

func (r *Remote) Marshal() []byte {
	return ssh.Marshal(r)
}

func (r *Remote) Unmarshal(payload []byte) error {
	return ssh.Unmarshal(payload, r)
}

type PassThrough struct {
}

func (p *PassThrough) RequestType() string {
	return string(PASSTHROUGH)
}

func (p *PassThrough) Marshal() []byte {
	return ssh.Marshal(p)
}

func (p *PassThrough) Unmarshal(payload []byte) error {
	return ssh.Unmarshal(payload, p)
}
