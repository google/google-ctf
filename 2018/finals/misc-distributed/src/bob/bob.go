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

package bob

import (
	"endpoint"
	"message"
	"rand"
)

type MagicFactory interface {
	Get() int64
}

type MagicFactoryIntRange struct {
	Rand       rand.Int
	LowerBound int64
	UpperBound int64
}

func (mf *MagicFactoryIntRange) Get() int64 {
	return mf.Rand.Get(mf.LowerBound, mf.UpperBound)
}

type NetworkFactory interface {
	Network() endpoint.Network
}

var gctfFlag = "CTF{Bob_Isnt_Really_Good_At_Security}"

type Bob struct {
	System endpoint.SystemAdmin

	ShowFlag bool

	MagicFactory   MagicFactory
	NetworkFactory NetworkFactory

	CurrentMessageNum int
	SpecialMessageNum int

	SpecialMagic int64

	LastMagicRequested int64

	GotAnswer bool
}

type SpecialParams struct {
	MessageNum int
	Magic      int64
}

func New(s endpoint.SystemAdmin, mf MagicFactory, nf NetworkFactory, specialParams *SpecialParams) *Bob {
	return &Bob{
		System:             s,
		ShowFlag:           false,
		CurrentMessageNum:  0,
		MagicFactory:       mf,
		NetworkFactory:     nf,
		SpecialMessageNum:  specialParams.MessageNum,
		SpecialMagic:       specialParams.Magic,
		LastMagicRequested: 0,
		GotAnswer:          true,
	}
}

var _ endpoint.Endpoint = (*Bob)(nil)

func (b *Bob) Name() string {
	return "bob"
}

func (b *Bob) Message(msg *message.Message) *message.Message {
	switch m := msg.Get().(type) {
	case *message.WhatToDoBob:
		return b.Ask(m)
	case *message.Response:
		return b.Answer(m)
	case *message.Error:
		if b.LastMagicRequested == b.SpecialMagic {
			// Accept an error answer as an answer. It is fine.
			b.GotAnswer = true
		}
		return message.Statusf("That's OK, I probably didn't send you the right thing... Just ask me again. :)")
	default:
		return message.Errorf("unsupported message type: %T", m)
	}
}

func (b *Bob) nextForward() *message.Message {
	if b.CurrentMessageNum > 3 && (b.CurrentMessageNum%b.SpecialMessageNum < 3 /* making sure it's hard to miss */) {
		return b.specialForward()
	}
	return b.normalForward()
}

func (b *Bob) specialForward() *message.Message {
	return &message.Message{
		Request: &message.Request{
			Magic: b.SpecialMagic,
		},
	}
}

func (b *Bob) normalForward() *message.Message {
	var x int64
	for {
		x = b.MagicFactory.Get()
		if x%b.SpecialMagic != 0 {
			break
		}
	}
	return &message.Message{
		Request: &message.Request{
			Magic: x,
		},
	}
}

func (b *Bob) Ask(*message.WhatToDoBob) *message.Message {
	if !b.GotAnswer {
		return &message.Message{
			Request: &message.Request{
				Magic: b.LastMagicRequested,
			},
		}
	}

	if b.ShowFlag {
		return &message.Message{
			Flag: &message.Flag{
				Flag: gctfFlag,
			},
		}
	}

	fw := b.nextForward()
	b.LastMagicRequested = fw.Request.Magic
	b.CurrentMessageNum++
	b.GotAnswer = false
	return fw
}

func (b *Bob) SecurityBreachReset(reason string) *message.Message {
	b.System.ChangeNetwork(b.NetworkFactory.Network())
	return message.Statusf("Security Breach Detected! Worker system reset requested. Reason = %q", reason)
}

func (b *Bob) Answer(m *message.Response) *message.Message {
	if m.Magic != b.LastMagicRequested {
		return b.SecurityBreachReset("incorrect 'magic'")
	}

	expectedWork := b.System.Work(m.Magic)
	if diff := message.DiffWorks(m.Work, expectedWork); len(diff) > 0 {
		return b.SecurityBreachReset("incorrect 'work'")
	}

	b.GotAnswer = true

	if m.Magic == b.SpecialMagic {
		// This is the challenge.
		return b.HandleSpecial()
	}

	return message.Statusf("Thanks")
}

func (b *Bob) HandleSpecial() *message.Message {
	b.ShowFlag = true
	return message.Statusf("Thank you very much :)")
}
