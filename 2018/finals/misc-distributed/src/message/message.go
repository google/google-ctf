// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package message

import (
	"fmt"
)

// oneof
type Message struct {
	// Generic messages
	Error         *Error         `json:"error,omitempty"`
	Status        *Status        `json:"status,omitempty"`
	CriticalError *CriticalError `json:"critical_error,omitempty"`

	// Used for polling Bob
	WhatToDoBob *WhatToDoBob `json:"what_to_do_bob,omitempty"`

	// Request
	Request *Request `json:"request,omitempty"`

	// Proof of work
	Response *Response `json:"response,omitempty"`

	Flag *Flag `json:"flag,omitempty"`
}

// use this for type assertions
func (m *Message) Get() interface{} {
	if m.Error != nil {
		return m.Error
	} else if m.CriticalError != nil {
		return m.CriticalError
	} else if m.Status != nil {
		return m.Status
	} else if m.WhatToDoBob != nil {
		return m.WhatToDoBob
	} else if m.Request != nil {
		return m.Request
	} else if m.Response != nil {
		return m.Response
	} else if m.Flag != nil {
		return m.Flag
	}
	return nil
}

func CriticalErrorf(code int64) *Message {
	s := fmt.Sprintf("Critical error. Please contact the CTF organizers! << code = %d >>", code)
	return &Message{CriticalError: &CriticalError{s}}
}

type CriticalError Error

func Errorf(format string, args ...interface{}) *Message {
	s := fmt.Sprintf(format, args...)
	return &Message{Error: &Error{s}}
}

func Statusf(format string, args ...interface{}) *Message {
	s := fmt.Sprintf(format, args...)
	return &Message{Status: &Status{s}}
}

// Message types
type WhatToDoBob struct{}

type Request struct {
	Magic int64 `json:"magic"`
}

type Response struct {
	Magic int64                `json:"magic"`
	Work  []*SingleWorkMessage `json:"work_log,omitempty"`
}

type Status struct {
	Message string `json:"message"`
}

type Error struct {
	Message string `json:"message"`
}

type Flag struct {
	Flag string `json:"flag"`
}
