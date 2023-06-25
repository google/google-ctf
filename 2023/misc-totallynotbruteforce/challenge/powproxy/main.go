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
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2"
)

var (
	target = flag.String("target", "https://misc-totallynotbruteforce.2023.ctfcompetition.com:1337/", "proxy target")
	listen = flag.String("listen", ":1337", "listen addr")
)

func main() {
	flag.Parse()

	u, err := url.Parse(*target)
	if err != nil {
		log.Fatalln("parsing target url failed", err)
	}

	client, conn, err := newClient(u)
	if err != nil {
		log.Fatalln(err)
	}

	chall, err := readLine(conn)
	if err != nil {
		log.Fatalln(err)
	}

	if strings.Contains(chall, "enabled") {
		err = solvePow(conn)
		if err != nil {
			log.Fatalln(err)
		}
	}

	// Check connectivity
	_, err = client.Get(*target)
	if err != nil {
		log.Fatalln(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		req := r.Clone(ctx)
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		req.RequestURI = ""

		res, err := client.Do(req)
		if err != nil {
			log.Println("request failed:", err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}

		w.WriteHeader(res.StatusCode)
		for k, vv := range res.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		io.Copy(w, res.Body)
	})
	log.Println("listening on", *listen)
	err = http.ListenAndServe(*listen, nil)
	if err != nil {
		log.Fatalln(err)
	}
}

func newClient(u *url.URL) (*http.Client, net.Conn, error) {
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("connection failed %w", err)
	}

	return &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				// Ignore all the above and always return the same shared connection.
				return c, nil
			},
		},
	}, c, nil
}

func readLine(conn net.Conn) (string, error) {
	var buf bytes.Buffer
	b := make([]byte, 1)
	for {
		_, err := conn.Read(b)
		if err != nil {
			return "", err
		}

		if b[0] == '\n' {
			break
		}

		_, err = buf.Write(b)
		if err != nil {
			return "", err
		}
	}
	return buf.String(), nil
}

func solvePow(conn net.Conn) error {
	var chall string
	for {
		s, err := readLine(conn)
		if err != nil {
			return err
		}

		if strings.Contains(s, "python3") && strings.Contains(s, "solve") {
			chall = strings.TrimPrefix(s, "    python3 <(curl -sSL https://goo.gle/kctf-pow) solve ")
			break
		}
	}

	log.Println("solving pow:", chall)
	ch, err := DecodeChallenge(chall)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte(ch.Solve().String() + "\n"))
	if err != nil {
		return err
	}

	for {
		s, err := readLine(conn)
		if err != nil {
			return err
		}

		if strings.Contains(s, "Correct") {
			break
		}
	}

	log.Println("pow ok")
	return nil
}
