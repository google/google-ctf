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
	"bob"
	"encoding/json"
	"endpoint"
	"flag"
	"fmt"
	"io"
	"log"
	"message"
	"net"
	"os"
	"rand"
	"system"
)

var Size = flag.Int("size", 10, "challenge size")
var SpecialMagic = flag.Int64("special_magic", 1*2*4*5*7*9, "special magic")

var Local = flag.Bool("local", false, "local version (stdio, stdin)")

var Tcp = flag.Bool("tcp", false, "TCP version (provide port flag as well")
var Port = flag.Int("port", 9191, "TCP port to listen on")

type Input struct {
	Endpoint string           `json:endpoint`
	Message  *message.Message `json:message`
}

type Endpoints []endpoint.Endpoint

func (es Endpoints) Get(name string) endpoint.Endpoint {
	for _, end := range es {
		if end.Name() == name {
			return end
		}
	}
	return nil
}

func runChallenge(r io.Reader, w io.Writer) {
	if *SpecialMagic == 0 {
		log.Panic("Special magic cannot be set to 0.")
	}

	defer func() {
		if r := recover(); r != nil {
			code := rand.DefaultIntRange.Get(1, 1000000000)

			js, _ := json.Marshal(message.CriticalErrorf(code))
			log.Fatalf("Critical Error: (code = %d): %v", code, r)
			fmt.Fprintln(w, string(js))
		}
	}()

	c := NewChallenge(rand.DefaultIntRange, *Size, *SpecialMagic)

	var msg *Input
	dec := json.NewDecoder(r)
	for {
		msg = nil
		err := dec.Decode(&msg)
		if err == io.EOF {
			// End of file!
			return
		}
		if err != nil {
			log.Fatal(err)
		}

		e := c.Endpoints.Get(msg.Endpoint)
		if e == nil {
			// Just ignore non-existing endpoints.
			continue
		}

		// Forward the message to the right endpoint and write back the response.
		response := e.Message(msg.Message)
		respJson, _ := json.Marshal(response)
		fmt.Fprintln(w, string(respJson))
	}
}

func tcpMain() {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: *Port})
	if err != nil {
		log.Panicf("Error creating a TCP socket: %v", err)
	}
	defer listener.Close()
	log.Printf("Listening on TCP address: %v", listener.Addr())

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Panicf("Error accepting a TCP connection: %v", err)
		}
		log.Printf("Accepted a new TCP connection [%v]!", conn.RemoteAddr())

		go func() {
			defer log.Printf("Connection closed [%v]!", conn.RemoteAddr())
			defer conn.Close()
			runChallenge(conn, conn)
		}()
	}
}

func stdioMain() {
	runChallenge(os.Stdin, os.Stdout)
}

func main() {
	flag.Parse()

	if /* not xor */ !(*Tcp != *Local) {
		log.Fatal("you need to set exactly one of --tcp, --local")
	}

	if *Tcp {
		tcpMain()
	} else if *Local {
		stdioMain()
	}
}

type Challenge struct {
	Bob       *bob.Bob
	System    *system.System
	Endpoints Endpoints
}

func factorial(n int64) int64 {
	if n > 20 {
		panic("requested too big factorial")
	}
	if n == 0 {
		return 1
	}
	return n * factorial(n-1)
}

func NewChallenge(r rand.Int, size int, specialMagic int64) *Challenge {
	if size < 5 {
		panic("the initial graph size is a bit too small, come on, make it at least 5")
	}

	nf := &system.RandDenseNetworkFactory{size}
	g := nf.Network()

	s := &system.System{Netw: g, SpecialMagic: specialMagic}
	b := bob.New(
		s,
		&bob.MagicFactoryIntRange{
			Rand:       r,
			LowerBound: 1,
			UpperBound: factorial(int64(size)),
		},
		nf,
		&bob.SpecialParams{
			// TODO(kele): find a way to create the magic properly
			Magic:      specialMagic,
			MessageNum: 20,
		})
	return &Challenge{
		Bob:       b,
		System:    s,
		Endpoints: Endpoints{b, s},
	}
}
