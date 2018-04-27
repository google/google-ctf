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



// Package main runs our puzzle server.
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"flag"
	pzl "./puzzle"
	"crypto"
	"encoding/binary"
)


var (
	solution = flag.String("solution", "CTF{zx2fn265ll7}", "The Flag!!")
	port     = flag.Int("port", 8080, "Port to listen on")
	puzzle   *pzl.Puzzle
)

func main() {
	var err error
	fmt.Print("Starting server...\n")
	flag.Parse()

	// Compute a seed for the puzzle.
	hasher := crypto.SHA256.HashFunc().New()
	hasher.Write([]byte(*solution))
	hash := hasher.Sum(make([]byte, 0, 32))
	seed := int64(binary.LittleEndian.Uint64(hash[0:8]))

	// Initialize our puzzle
	if puzzle, err = pzl.NewPuzzle(1024, &seed); err != nil {
		fmt.Printf("Puzzle generation failed with error: %s\n", err.Error())
		return
	}

	// Server Handlers
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/check", checkHandler)

	fmt.Printf("Listening on port %d\n", *port)
	fmt.Print(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}

func indexHandler(w http.ResponseWriter, _ *http.Request) {
	pem, _ := puzzle.GetPubkeyPem()
	fmt.Fprintf(w, pzl.HomePage, pem)
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	var req pzl.CheckRequest
	var body []byte
	var password string

	if body, err = ioutil.ReadAll(r.Body); err != nil {
		http.Error(w, "Failed to read request body.", 400)
		return
	}

	if err = json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid json format.", 400)
		return
	}

	if err = puzzle.VerifySignature(req.Signature); err != nil {
		http.Error(w, fmt.Sprintf("failure to decrypt password: %s", err.Error()), 400)
		return
	}

	if password != puzzle.Solution() {
		fmt.Fprint(w, `{"CheckSucceeded" : 0}`)
	} else {
		fmt.Fprintf(w, `{"CheckSucceeded" : 1, "Flag" : "%s"}`, *solution)
	}
}
