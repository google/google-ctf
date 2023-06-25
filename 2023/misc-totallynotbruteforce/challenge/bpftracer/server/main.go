// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bpftracer/proto"
	"context"
	"crypto/subtle"
	"flag"
	"log"
	"net"
	"regexp"
	"strings"

	"google.golang.org/grpc"
)

var (
	shard   = flag.Int("chunk_shard", 0, "flagchecker shard")
	length  = flag.Int("chunk_length", 0, "length of flag to check in this shard")
	address = flag.String("address", "localhost:1337", "listen address")
	secret  = flag.String("flag", "", "flag chunk to check")

	flagPattern = regexp.MustCompile("^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}]*$")
)

type server struct {
	proto.UnimplementedFlagServiceServer
	flagPrefix string
	length     int
	shard      int
}

func (s *server) CheckFlag(ctx context.Context, req *proto.CheckFlagRequest) (*proto.CheckFlagResponse, error) {
	f := req.GetFlag()
	if f == "" {
		return &proto.CheckFlagResponse{Ok: false}, nil
	}

	prefix := []byte(cycled(f, s.length*(s.shard+1)))
	result := subtle.ConstantTimeCompare(prefix, []byte(s.flagPrefix))
	return &proto.CheckFlagResponse{Ok: result == 1}, nil
}

func (s *server) Ping(ctx context.Context, req *proto.Empty) (*proto.Empty, error) {
	return req, nil
}

func cycled(s string, l int) string {
	var result strings.Builder
	for i := 0; i < l; i++ {
		result.WriteByte(s[i%len(s)])
	}

	return result.String()
}

func main() {
	flag.Parse()
	if *secret == "" {
		log.Fatalln("invalid empty flag chunk")
	}

	if !flagPattern.MatchString(*secret) {
		log.Fatalln("invalid flag")
	}

	l := *length
	if l == 0 {
		l = len(*secret)
	}
	flagPrefix := cycled(*secret, l*(*shard+1))
	log.Println("checking for chunk:", flagPrefix)

	listener, err := net.Listen("tcp", *address)
	if err != nil {
		log.Fatalln("failed to listen:", err)
	}
	s := grpc.NewServer()
	proto.RegisterFlagServiceServer(s, &server{
		flagPrefix: flagPrefix,
		length:     l,
		shard:      *shard,
	})
	log.Println("listening on", *address)
	s.Serve(listener)
}
