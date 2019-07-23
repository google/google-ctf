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

// Binary solve solves the Doomed to Repeat It challenge.
// It solves it with high probability (99.585%). If it fails, just run it again.
// It needs the boards.bin file to have already been generated, by the gen
// binary.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/websocket"

	"memory/game"
)

// See gen.go
const numSeeds = 1 << 17

var target = flag.String("target", "ws://localhost:8080",
	"scheme host [port] of target")

type entry struct {
	board []byte
	dupe  bool
}

// index must be < game.BoardSize.
// return value guaranteed to be in range.
func guess(conn *websocket.Conn, index int) byte {
	x := index % game.BoardWidth
	y := index / game.BoardWidth
	req := game.Req{
		Op: "guess",
		Body: game.GuessBody{
			X: x,
			Y: y,
		},
	}
	if err := conn.WriteJSON(req); err != nil {
		log.Fatalf("Couldn't WriteJSON: %v", err)
	}

	resp := game.Resp{}
	if err := conn.ReadJSON(&resp); err != nil {
		log.Fatalf("Couldn't ReadJSON: %v", err)
	}
	if resp.Message != "" {
		log.Printf("Message: %v", resp.Message)
	}
	if resp.Done {
		log.Print("Done")
	}
	if len(resp.Board) != game.BoardSize {
		log.Fatal("Board has bad size")
	}
	v := resp.Board[index]
	if v < 0 || v >= game.BoardSize/2 {
		log.Fatal("Value in board out of range")
	}
	log.Printf("Guessed x %d y %d got %d TurnsUsed %d MaxTurns %v\n",
		x, y, v, resp.TurnsUsed, resp.MaxTurns)
	return byte(v)
}

// Given a board that's at least 5 elements long, return an id that identifies
// the first 5 elements.
func boardToKey(board []byte) uint64 {
	first5 := make([]byte, 8)
	copy(first5, board[:5])
	return binary.LittleEndian.Uint64(first5)
}

func main() {
	flag.Parse()

	boards, err := ioutil.ReadFile("boards.bin")
	if err != nil {
		log.Fatalf("Couldn't read file: %v", err)
	}
	if len(boards) != game.BoardSize*numSeeds {
		log.Fatal("Bad boards length")
	}
	decode := map[uint64]*entry{}

	for i := 0; i < numSeeds; i++ {
		board := boards[i*game.BoardSize : (i+1)*game.BoardSize]
		key := boardToKey(board)
		_, ok := decode[key]
		if ok {
			decode[key].dupe = true
		} else {
			decode[key] = &entry{board: board}
		}
	}
	numDupes := numSeeds - len(decode)
	ratioDupes := float64(numDupes) / float64(numSeeds)
	ratioInitials := 1 - ratioDupes
	fmt.Printf("numDupes: %d ratioDupes: %f ratioInitials: %f\n",
		numDupes, ratioDupes, ratioInitials)

	ourl, err := url.Parse(*target)
	if err != nil {
		log.Fatalf("Clouldn't parse target: %v", err)
	}
	if ourl.Scheme == "wss" {
		ourl.Scheme = "https"
	} else if ourl.Scheme == "ws" {
		ourl.Scheme = "http"
	} else {
		log.Fatal("Bad scheme")
	}
	hdr := http.Header{}
	hdr.Add("Origin", ourl.String())
	conn, _, err := websocket.DefaultDialer.Dial(*target+"/ws", hdr)
	if err != nil {
		log.Fatalf("Couldn't dial: %v", err)
	}
	defer conn.Close()

	board := make([]byte, 5)
	for i := 0; i < 5; i++ {
		// This isn't optimal play, because if on the guess of index 2 we see
		// a number from index 0 or 1, we're not going back to guess it. But this
		// doesn't really matter, because we still have a very high chance of
		// success, and going back to match that previous number would hardly raise
		// the chance of success.
		board[i] = guess(conn, i)
	}
	ent, ok := decode[boardToKey(board)]
	if !ok {
		log.Fatal("Couldn't find key")
	}
	if ent.dupe {
		log.Print("Warning, entry was dupe")
	}
	board = ent.board

	// Map from entry value to [first entry pos, second entry pos]
	matcher := map[byte][]int{}
	for i := 0; i < game.BoardSize/2; i++ {
		matcher[byte(i)] = []int{-1, -1}
	}
	for i, v := range board {
		if v >= game.BoardSize/2 {
			log.Fatal("Board element too large")
		}
		me := matcher[v]
		if me[0] < 0 {
			me[0] = i
		} else if me[1] < 0 {
			me[1] = i
		} else {
			log.Fatal("3 board elements have same value")
		}
	}
	for i := 0; i < game.BoardSize/2; i++ {
		me := matcher[byte(i)]
		if me[0] < 0 || me[1] < 0 {
			log.Fatal("Match entry not filled in")
		}
	}

	me4 := matcher[board[4]]
	if me4[0] == 4 {
		if guess(conn, me4[1]) != board[4] {
			log.Fatal("Guess me4[1] wrong")
		}
	} else if me4[1] == 4 {
		if guess(conn, me4[0]) != board[4] {
			log.Fatal("Guess me4[0] wrong")
		}
	} else {
		log.Fatal("me4 doesn't have 4")
	}

	// The board values that were solved by first 6 guesses.
	alreadySolved := map[byte]struct{}{}
	if board[0] == board[1] {
		alreadySolved[board[0]] = struct{}{}
	}
	if board[2] == board[3] {
		alreadySolved[board[2]] = struct{}{}
	}
	alreadySolved[board[4]] = struct{}{}

	for i := byte(0); i < game.BoardSize/2; i++ {
		if _, ok = alreadySolved[i]; ok {
			continue
		}
		if guess(conn, matcher[i][0]) != i {
			log.Fatal("Guess of first in pair was wrong")
		}
		if guess(conn, matcher[i][1]) != i {
			log.Fatal("Guess of second in pair was wrong")
		}
	}
}
