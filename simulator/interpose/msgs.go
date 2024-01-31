package interpose

import "golang.org/x/crypto/ssh"

type Style string

const (
	PASSTHROUGH Style = "pass-through"
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

const InvocationReq = "invocation"

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
