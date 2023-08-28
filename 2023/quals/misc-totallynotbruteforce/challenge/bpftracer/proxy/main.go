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
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	index = `
<html>
  <body>
    <form action="/">
      <input placeholder="CTF{...}" name="flag">
      <input type="submit" value="Guess">
    </form>
  </body>
</html>
`
	pattern = regexp.MustCompile(`\d+`)
	listen  = flag.String("listen", "", "listen addr")
	fd      = flag.Int("fd", -1, "listen fd")
)

func main() {
	log.Println("starting proxy")
	var servers []string
	flag.Func("server", "List of servers to connect to", func(s string) error {
		for _, s := range strings.Split(s, ",") {
			servers = append(servers, s)
		}
		return nil
	})
	flag.Parse()
	if len(servers) == 0 {
		log.Fatal("no servers specified.")
	}

	if *fd < 0 && *listen == "" {
		log.Fatal("must specify listen addr or fd.")
	}

	log.Println("connecting to flag servers:", strings.Join(servers, ", "))

	var clients []proto.FlagServiceClient
	for _, addr := range servers {
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalln("failed to connect to", addr, "error:", err)
		}
		defer conn.Close()
		clients = append(clients, proto.NewFlagServiceClient(conn))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		f, ok := params["flag"]
		if !ok || len(f) < 1 {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, index)
			return
		}

		result := true
		for _, client := range clients {
			req := &proto.CheckFlagRequest{Flag: f[0]}
			res, err := client.CheckFlag(r.Context(), req)
			if err != nil {
				log.Println("error while checking flag:", err, "request:", req)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			result = result && res.GetOk()
		}

		if result {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
			return
		}

		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()

		timeout := "5"
		if ts, ok := params["t"]; ok && len(ts) > 0 {
			timeout = ts[0]
		}

		if !pattern.Match([]byte(timeout)) {
			log.Println(timeout, "did not match the pattern")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		f, err := os.CreateTemp("", "probe*.bt")
		if err != nil {
			log.Println("can't write a temporary file", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer os.Remove(f.Name())

		s := "interval:s:" + timeout + " { exit() } profile:hz:99 /pid == $1/ { @[ustack] = count() }\n"
		f.WriteString(s)
		f.Close()

		log.Println("executing probe:", s)
		c, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(
			c,
			"bpftrace",
			f.Name(),
			strconv.Itoa(os.Getpid()),
		).CombinedOutput()
		if err != nil {
			log.Println("error while tracing:", err, "output:", string(out))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Write(out)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		for _, client := range clients {
			req := &proto.Empty{}
			_, err := client.Ping(r.Context(), req)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintln(w, "error")
				return
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	var err error
	h2 := &http2.Server{}
	if *listen != "" {
		log.Println("listening on", *listen)
		err = http.ListenAndServe(*listen, h2c.NewHandler(mux, h2))
	} else {
		log.Println("connection on fd", *fd)
		var c net.Conn
		c, err = net.FileConn(os.NewFile(uintptr(*fd), "listen fd"))
		if err != nil {
			log.Fatalln(err)
		}
		h2.ServeConn(c, &http2.ServeConnOpts{Handler: mux})
	}

	if err != nil {
		log.Fatalln(err)
	}
}
