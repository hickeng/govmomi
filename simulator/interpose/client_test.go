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
	"net/netip"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticMock(t *testing.T) {
	os.Setenv("VCSIM_INTERPOSE_DEBUG_LOGS", "true")

	handlers := &Handlers{}

	// create server
	server, err := NewServer(netip.MustParseAddr("127.0.0.1"), handlers)
	require.Nil(t, err, "unable to create server")

	config, _ := ConstructContainerConfig(server.IP(), server.Port())
	ctx := context.WithValue(context.Background(), configCtxKey, config)

	// register mock handler
	staticMsg := &Static{
		ExitCode: 0,
		Stdout:   []byte("foo"),
		Stderr:   []byte{},
	}

	handlerFired := false
	var invocation *Invocation
	hfunc := func(i *Invocation) (bool, Message) {
		invocation = i
		handlerFired = true
		return true, staticMsg
	}

	handlers.RegisterHandler("test-handler", hfunc)

	// invoke client
	mockTarget := "/some/mock"
	mockArgs := []string{"a", "b", "c"}
	mockEnv := []string{"1", "2", "3"}
	mockPwd := "/mockdir"
	style, result, err := newClient(ctx, mockTarget, mockArgs, mockEnv, mockPwd)

	// assert hander fires
	require.True(t, handlerFired, "expected handler to have processed")
	require.Equal(t, STATIC, style, "expected static mock response")
	require.Nil(t, err, "expected client to invoke cleanly")

	// assert invocation details at server match
	assert.Equal(t, mockTarget, invocation.Target, "expected targets to match")
	assert.Equal(t, mockArgs, invocation.Args, "expected args to match")
	assert.Equal(t, mockEnv, invocation.Env, "expected env to match")
	assert.Equal(t, mockPwd, invocation.Pwd, "expected pwd to match")

	// assert response from handler shows at client
	assert.Equal(t, staticMsg.ExitCode, result.exitCode(), "expected exit codes to match")

	resOut := make([]byte, len(staticMsg.Stdout)+2)
	n, err := result.stdout().Read(resOut)
	assert.Equal(t, len(staticMsg.Stdout), n)
	assert.True(t, err == nil || (err.Error() == "EOF" && n == 0), "expected to be able to read from result stdout")
	assert.Equal(t, staticMsg.Stdout, resOut[:n], "expected stdout to match")

	resErr := make([]byte, len(staticMsg.Stderr)+2)
	n, err = result.stderr().Read(resErr)
	assert.Equal(t, len(staticMsg.Stderr), n)
	assert.True(t, err == nil || (err.Error() == "EOF" && n == 0), "expected to be able to read from result stderr")
	assert.Equal(t, staticMsg.Stderr, resErr[:n], "expected stderr to match")
}
