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
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"io/ioutil"

	"google.golang.org/protobuf/encoding/prototext"
)

var keyFile string

func init() {
	flag.StringVar(&keyFile, "key", "server_ecdh_private.textproto", "output key filename")
}

func main() {
	flag.Parse()

	priv, x, y, err := elliptic.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		panic(err)
	}

	key := &pb.EcdhPrivateKey{
		Key: &pb.EcdhKey{
			Curve: pb.EcdhKey_SECP224R1,
			Public: &pb.Point{
				X: x.Bytes(),
				Y: y.Bytes(),
			},
		},
		Private: priv,
	}
	data, err := prototext.Marshal(key)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(keyFile, data, 0644)
	if err != nil {
		panic(err)
	}
}
