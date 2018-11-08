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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"message"
	"net"
	"time"
)

var ShouldLog = false

var port = flag.Int("port", 9191, "port")
var ip = flag.String("ip", "127.0.0.1", "ip address")
var secret = flag.Int("secret", 0, "secret (it might save you some time, but you don't really need to crack this, pinky promise)")

type WrappedMessage struct {
	Endpoint string           `json:"endpoint"`
	Message  *message.Message `json:"message"`
}

type Interaction struct {
	Error   error
	Decoder *json.Decoder
	Writer  io.Writer
}

func (i *Interaction) Read() *message.Message {
	if i.Error != nil {
		return nil
	}
	var msg *message.Message
	if err := i.Decoder.Decode(&msg); err != nil {
		i.Error = err
		return nil
	}
	return msg
}

func (i *Interaction) Write(endpoint string, m *message.Message) {
	if i.Error != nil {
		return
	}
	msg := WrappedMessage{Endpoint: endpoint, Message: m}
	respJson, _ := json.Marshal(msg)
	s := string(respJson)
	if ShouldLog {
		log.Printf("Sending %q to %q", s, endpoint)
	}
	_, err := fmt.Fprintln(i.Writer, string(respJson))
	if err != nil {
		i.Error = err
	}
}

func main() {
	flag.Parse()

	if *secret == 9235012 {
		ShouldLog = true
	}

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(*ip), Port: *port})
	if err != nil {
		log.Fatalf("Could not establish TCP connection: %v", err)
	}
	defer conn.Close()

	log.Println("Acting as a proxy...")

	askBob := &message.Message{WhatToDoBob: &message.WhatToDoBob{}}
	interaction := &Interaction{Decoder: json.NewDecoder(conn), Writer: conn}
	for {
		interaction.Write("bob", askBob)
		req := interaction.Read()
		interaction.Write("nodenetwork", req)
		resp := interaction.Read()
		interaction.Write("bob", resp)
		responseFromBob := interaction.Read()

		if ShouldLog {
			log.Println("Response from Bob:", responseFromBob.Get())
		}

		time.Sleep(time.Millisecond * 200)
	}
}
