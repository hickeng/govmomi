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
	"sync"
)

// HandlerFunc is a callback function provided by test cases to determine what to do for a given invocation
// It takes an invocation description and return:
// bool - true if the handler has processed the invocation (prevents further handlers being called)
// Message - response details. If handled, but with nil Message it's treated as a pass-through
type HandlerFunc func(*Invocation) (bool, Message)

type Handlers struct {
	sync.RWMutex

	callbacks map[string]HandlerFunc
	// TODO: add a means of indicating order of processing
	fallback HandlerFunc
}

func (h *Handlers) RegisterHandler(id string, handler HandlerFunc) {
	h.Lock()
	defer h.Unlock()

	if h.callbacks == nil {
		h.callbacks = make(map[string]HandlerFunc)
	}

	if _, present := h.callbacks[id]; present {
		panic("duplicate interpose handler registered")
	}

	h.callbacks[id] = handler

}

// unregisterHandler deletes the handler entry corresponding to the provided id string
func (h *Handlers) UnregisterHandler(id string) {
	h.Lock()
	defer h.Unlock()

	if h.callbacks == nil {
		return
	}

	delete(h.callbacks, id)
}

// setFallbackHandler sets the default handler to use if no other will process an invocation.
// providing a nil handler reverts to default behaviour (pass-through)
func (h *Handlers) SetFallbackHandler(handler HandlerFunc) {
	h.Lock()
	defer h.Unlock()

	h.fallback = handler
}

// processInvocation works through the handlers until it finds one that accepts the invocations.
// If no such handler is present, it uses the fallback handler if specified or a pass-through response if not.
// bool - whether a non-fallback handler was found
// string - the ID of a non-fallback handler if used
func (h *Handlers) processInvocation(invocation *Invocation) (bool, string, Message) {
	h.RLock()
	defer h.RUnlock()

	for id, handler := range h.callbacks {
		processed, msg := handler(invocation)
		if processed {
			return true, id, msg
		}
	}

	if h.fallback != nil {
		_, msg := h.fallback(invocation)
		return false, "", msg
	}

	return false, "", &PassThrough{}
}
