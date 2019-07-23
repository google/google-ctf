// Copyright 2019 Google LLC
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

// Binary memory is a server for the game Memory, a fun and secure web game.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"

	"memory/game"
)

var (
	upgrader      = websocket.Upgrader{CheckOrigin: checkOrigin}
	staticHandler = http.FileServer(http.Dir("static"))
)

// r must be non-nil. Returns true if this is on App Engine and non-https.
// We enforce https to ensure game integrity.
func needsHttpsRedir(r *http.Request) bool {
	h := r.Header.Get("X-Forwarded-Proto")
	// We only enforce https when running on App Engine. When running locally
	// http is allowed for convenience.
	if h != "" && h != "https" {
		return true
	}
	return false
}

// We vigorously defend against CSRF/XSRF with strict origin checks.
// Note that without this, we would have severe vulnerabilities, because
// browsers don't enforce the same origin policy on websockets.
// Security is our #1 priority.
func checkOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	p := r.Header.Get("X-Forwarded-Proto")
	h := r.Host
	if o == "" || h == "" {
		log.Print("Websocket missing origin and/or host")
		return false
	}
	ou, err := url.Parse(o)
	if err != nil {
		log.Printf("Couldn't parse url: %v", err)
		return false
	}
	if p != "" && ou.Scheme != "https" {
		log.Print("Https websocket missing https origin")
		return false
	}
	if ou.Host != h {
		log.Print("Origin doesn't match host")
		return false
	}
	// TODO: Origin is a 3 tuple (scheme, host, port). Figure out how to check the
	// port.
	// TODO: We should enforce https origin on https ws even on non-App Engine.
	return true
}

type rootHandler struct {
	flag string
}

func (h *rootHandler) handleWs(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Couldn't upgrade: %v", err)
		return
	}
	game.Run(conn, h.flag)
}

func (h *rootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// TODO: What about DNS rebinding attacks?
	if needsHttpsRedir(r) {
		// A shallow copy of URL is fine because it's not being retained.
		newUrl := *r.URL
		newUrl.Host = r.Host
		newUrl.Scheme = "https"
		http.Redirect(w, r, newUrl.String(), 302)
		return
	}
	if r.URL.Path == "/ws" {
		h.handleWs(w, r)
		return
	}
	staticHandler.ServeHTTP(w, r)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {
	// flag.txt should have no newline
	flag, err := ioutil.ReadFile("flag.txt")
	if err != nil {
		log.Fatalf("Couldn't read flag: %v", err)
	}

	http.HandleFunc("/_ah/health", healthCheckHandler)
	http.Handle("/", &rootHandler{flag: string(flag)})
	log.Print("Listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
