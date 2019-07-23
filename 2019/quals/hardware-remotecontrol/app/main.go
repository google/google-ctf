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

// Author: zuan@google.com

// Package main contains the HTTP service and electrical simulation logic for this CTF challenge.
package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/go-daq/crc8"      // For CRC8 calculation in verifying the packet
	"google.golang.org/appengine" // Required external App Engine library
)

func main() {
	http.HandleFunc("/", http.NotFound)
	http.HandleFunc("/SendIRCommand", sendIRCommandHandler)
	appengine.Main() // Starts the server to receive requests
}

func sendIRCommandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST method only", http.StatusMethodNotAllowed)
		return
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read command", http.StatusInternalServerError)
		return
	}

	sh := string(b[:])
	cmdbytes := make([]byte, hex.DecodedLen(len(sh)))
	_, err2 := hex.Decode(cmdbytes, []byte(sh))
	if err2 != nil {
		http.Error(w, "Command not in hex encoding", http.StatusUnprocessableEntity)
		return
	}

	if len(cmdbytes) < 4 {
		http.Error(w, "Command too short", http.StatusUnprocessableEntity)
		return
	}

	if cmdbytes[0] != 0x55 {
		http.Error(w, "Incorrect command magic byte", http.StatusUnprocessableEntity)
		return
	}

	if len(cmdbytes) != int(cmdbytes[1]) {
		http.Error(w, "Command length incorrect", http.StatusUnprocessableEntity)
		return
	}

	tbl := crc8.MakeTable(0x07)
	csum := crc8.Checksum(cmdbytes[0:len(cmdbytes)-1], tbl)
	if csum != cmdbytes[len(cmdbytes)-1] {
		http.Error(w, "Incorrect command checksum", http.StatusUnprocessableEntity)
		return
	}

	// We run simulation for 2 seconds
	s := NewSimulator(2.0)
	s.hubBSTx.appendPacket(cmdbytes[2 : len(cmdbytes)-1])
	s.runSim()

	if s.remoteButtonReceived {
		// Print the flag
		fmt.Fprint(w, "CTF{1R_><CVR_in_I0T_Hub_1s_f3a7ure_n0t_bug}")
		return
	}

	fmt.Fprint(w, hex.EncodeToString(s.resultReply))
}
