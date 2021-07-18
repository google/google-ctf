// Copyright 2021 Google LLC
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
	"crypto-tiramisu/pb"
	"crypto-tiramisu/server"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/encoding/prototext"
)

var flagFile string
var keyFile string

const maxMessageLengh = 10 * 1024 * 1024

func writeMessage(w io.Writer, m proto.Message) error {
	if err := binary.Write(w, binary.LittleEndian, uint32(proto.Size(m))); err != nil {
		return fmt.Errorf("failed to write message length, binary.Write() = %v, want nil err", err)
	}
	buf, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to serialize message, proto.Marshal(%v) = %v, want nil err", m, err)
	}
	n, err := w.Write(buf)
	if n != len(buf) || err != nil {
		return fmt.Errorf("failed to write serialized message, w.Write(%X) = %v, %v, want n=%d and nil error", buf, n, err, len(buf))
	}
	return nil
}

func readMessage(r io.Reader, m proto.Message) error {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return fmt.Errorf("failed to read length, binary.Read(buf) = %v, want nil error", err)
	}
	if length > maxMessageLengh {
		return fmt.Errorf("want legnth <= %d, got %d", maxMessageLengh, length)
	}
	buf := make([]byte, length)
	if n, err := r.Read(buf); n != len(buf) || err != nil {
		return fmt.Errorf("failed to read serialized message, r.Read(buf) = %v, %v, want n=%d and nil error", n, err, len(buf))
	}
	if err := proto.Unmarshal(buf, m); err != nil {
		return fmt.Errorf("failed to unmarshal message, proto.Unmarshal(%X, m) = %v, want nil error", buf, err)
	}
	return nil
}

func runSession(server *server.Server, r io.Reader, w io.Writer) error {
	serverHello := server.ServerHello()
	if err := writeMessage(w, serverHello); err != nil {
		return fmt.Errorf("writeMessage(w, serverHello=%X)=%v, want nil err", serverHello, err)
	}

	clientHello := &pb.ClientHello{}
	if err := readMessage(r, clientHello); err != nil {
		return fmt.Errorf("readMessage(r, clientHello)=%v, want nil err", err)
	}

	if err := server.EstablishChannel(clientHello); err != nil {
		return fmt.Errorf("server.EstablishChannel(clientHello=%X)=%v, want nil err", clientHello, err)
	}

	for {
		clientMsg := &pb.SessionMessage{}
		if err := readMessage(r, clientMsg); err != nil {
			return fmt.Errorf("readMessage(r, clientMsg)=%v, want nil err", err)
		}

		serverMsg := server.EchoSessionMessage(clientMsg)
		if err := writeMessage(w, serverMsg); err != nil {
			return fmt.Errorf("writeMessage(w, serverMsg=%X)=%v, want nil err", serverMsg, err)
		}
	}
}

func init() {
	flag.StringVar(&flagFile, "flag", "/flag", "flag filename")
	flag.StringVar(&keyFile, "key", "/server_ecdh_private.textproto", "input key filename")
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			// Uncomment to catch panics during development.
			// panic(r)
		}
	}()

	flag.Parse()

	f, err := ioutil.ReadFile(flagFile)
	if err != nil {
		panic(err)
	}

	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		panic(err)
	}

	key := &pb.EcdhPrivateKey{}
	if err = prototext.Unmarshal(keyData, key); err != nil {
		panic(err)
	}

	server, err := server.NewServer(strings.TrimSpace(string(f)), key)
	if err != nil {
		panic(err)
	}

	err = runSession(server, os.Stdin, os.Stdout)
	if err != nil {
		panic(err)
	}
}
