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
	"crypto-tonality/challenger"
	"crypto-tonality/pb"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/golang/protobuf/proto"
)

var flagFile string

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

func runSession(chal *challenger.Challenger, r io.Reader, w io.Writer) error {
	hello := chal.Hello(&pb.HelloRequest{})
	if err := writeMessage(w, hello); err != nil {
		return fmt.Errorf("writeMessage(w, hello=%X)=%v, want nil err", hello, err)
	}

	signReq := &pb.SignRequest{}
	if err := readMessage(r, signReq); err != nil {
		return fmt.Errorf("readMessage(r, signReq)=%v, want nil err", err)
	}

	signRes := chal.SignFirstMessage(signReq)
	if err := writeMessage(w, signRes); err != nil {
		return fmt.Errorf("writeMessage(w, signRes=%X)=%v, want nil err", signRes, err)
	}

	verifyReq := &pb.VerifyRequest{}
	if err := readMessage(r, verifyReq); err != nil {
		return fmt.Errorf("readMessage(r, verifyReq)=%v, want nil err", err)
	}

	verifyRes := chal.VerifySecondMessage(verifyReq)
	if err := writeMessage(w, verifyRes); err != nil {
		return fmt.Errorf("writeMessage(w, verifyRes=%X)=%v, want nil err", verifyRes, err)
	}
	return nil
}

func init() {
	flag.StringVar(&flagFile, "flag", "/flag", "flag filename")
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

	chal, err := challenger.NewChallenger(strings.TrimSpace(string(f)))
	if err != nil {
		panic(err)
	}

	err = runSession(chal, os.Stdin, os.Stdout)
	if err != nil {
		panic(err)
	}
}
