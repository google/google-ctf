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

package system

import (
	"endpoint"
	"message"
	"sort"
)

type System struct {
	Netw         endpoint.Network
	SpecialMagic int64
}

var _ endpoint.Endpoint = (*System)(nil)

func (s *System) Name() string {
	return "nodenetwork"
}

func (s *System) Message(msg *message.Message) *message.Message {
	switch m := msg.Get().(type) {
	case *message.Request:
		return s.MessageWork(m)
	default:
		return message.Errorf("unsupported message type: %T", m)
	}
}

func (s *System) MessageWork(m *message.Request) *message.Message {
	if m.Magic == 0 {
		return message.Errorf("Magic cannot be 0.")
	}

	if m.Magic == s.SpecialMagic {
		return message.Errorf("I will not send this to Bob through a proxy, since this would cause Bob to reveal a secret flag.")
	} else if m.Magic%s.SpecialMagic == 0 {
		// We don't really want to gave the solution that easily. Make them work a bit.
		work := s.Work(m.Magic)
		specialWork := s.Work(s.SpecialMagic)
		if diff := message.DiffWorks(work, specialWork); len(diff) == 0 {
			return message.Errorf("I see what you did there.")
		}
	}

	work := s.Work(m.Magic)
	return &message.Message{
		Response: &message.Response{
			Magic: m.Magic,
			Work:  work,
		},
	}
}

func (s *System) Work(magic int64) []*message.SingleWorkMessage {
	n := s.Netw.Size()

	rounds := n
	var trace []*message.SingleWorkMessage
	for r := 1; r <= rounds; r++ {
		for i := 0; i < n; i++ {
			w := s.singleNodeWork(i, r, magic)
			trace = append(trace, w...)
		}
	}
	sort.Slice(trace, message.WorkCmp(trace))
	return trace
}

func (s *System) singleNodeWork(nodeID int, round int, magic int64) []*message.SingleWorkMessage {
	var work []*message.SingleWorkMessage
	for _, neighbour := range s.Netw.Neighbours(nodeID) {
		if magic%int64(neighbour) != 0 {
			continue
		}
		if magic%int64(round) != 0 {
			continue
		}
		work = append(work,
			&message.SingleWorkMessage{
				Round: round,
				From:  nodeID,
				To:    neighbour,
			})
	}
	return work
}

func (s *System) ChangeNetwork(network endpoint.Network) {
	s.Netw = network
}

func (s *System) Network() endpoint.Network {
	return s.Netw
}

var _ endpoint.SystemAdmin = (*System)(nil)
