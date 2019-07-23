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

// Package game contains the game logic for the game Memory.
package game

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gorilla/websocket"

	"memory/random"
)

const (
	BoardWidth                = 7
	BoardHeight               = 8
	BoardSize                 = BoardWidth * BoardHeight // even
	maxTurns                  = 60
	maxTurnTime time.Duration = 10 * time.Second
)

// Req is the json format that the client sends in the websocket.
type Req struct {
	Op   string      `json:"op"`
	Body interface{} `json:"body"`
}

// Resp is the json format that is sent to the client in the websocket.
type Resp struct {
	Width int `json:"width"`
	// Height can be calculated using board size, so don't send it
	Board       []int   `json:"board"` // -1 means hidden
	MaxTurns    int     `json:"maxTurns"`
	MaxTurnTime float64 `json:"maxTurnTime"` // seconds
	TurnsUsed   int     `json:"turnsUsed"`
	Done        bool    `json:"done"`
	Message     string  `json:"message"`
	// A list of [x,y] pairs that need to be cleared after display
	Clear [][]int `json:"clear"`
}

// GuessBody is the json format of the body field of Req during the guess
// operation.
type GuessBody struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type board struct {
	nums    []int
	visible []bool
}

func init() {
	if BoardSize%2 != 0 {
		panic("BoardSize must be even")
	}
}

func newBoard() (*board, error) {
	rand, err := random.New()
	if err != nil {
		return nil, fmt.Errorf("couldn't create random: %v", err)
	}
	b := &board{
		nums:    make([]int, BoardSize),
		visible: make([]bool, BoardSize),
	}
	// BoardSize is even
	for i, _ := range b.nums {
		b.nums[i] = i / 2
	}
	// https://github.com/golang/go/wiki/SliceTricks#shuffling
	for i := BoardSize - 1; i > 0; i-- {
		j := rand.UInt64n(uint64(i) + 1)
		b.nums[i], b.nums[j] = b.nums[j], b.nums[i]
	}
	return b, nil
}

func (b *board) forResp() []int {
	res := make([]int, BoardSize)
	// Assume nums and visible are right size
	for i, num := range b.nums {
		if b.visible[i] {
			res[i] = num
		} else {
			res[i] = -1
		}
	}
	return res
}

// Run runs the game for a single user who is attached to conn.
// conn must be non-nil. conn will be closed when done.
func Run(conn *websocket.Conn, flag string) {
	defer conn.Close()
	board, err := newBoard()
	if err != nil {
		log.Printf("Couldn't create board: %v", err)
		return
	}

	// During the first guess of a pair, this is -1, during the second guess of a
	// pair, this is the first guess of the pair.
	oldIndex := -1
	// The deadline is defined outside the loop, because otherwise the network
	// writes wouldn't be counted toward the deadline, leading to time extension
	// exploits.
	turnDeadline := time.Now().Add(maxTurnTime)
	turnsUsed := 0
	foundNum := 0
	done := false
	for !done {
		// Add 5 seconds so the websocket doesn't time out too fast.
		if err := conn.SetReadDeadline(turnDeadline.Add(5 * time.Second)); err != nil {
			log.Printf("Couldn't set read deadline: %v", err)
			return
		}
		var rawBody json.RawMessage
		req := Req{Body: &rawBody}
		if err := conn.ReadJSON(&req); err != nil {
			log.Printf("Couldn't read json msg: %v", err)
			return
		}

		var boardForResp []int
		clear := [][]int{}
		message := ""

		switch req.Op {
		case "info":
			// Don't change anything, just respond.
			boardForResp = board.forResp()
		case "guess":
			var guessBody GuessBody
			if err := json.Unmarshal(rawBody, &guessBody); err != nil {
				log.Printf("Couldn't read json guess body: %v", err)
				return
			}
			index := guessBody.Y*BoardWidth + guessBody.X
			if index < 0 || index >= BoardSize {
				log.Printf("Guess out of bounds: %d y: %d x: %d",
					index, guessBody.Y, guessBody.X)
				return
			}
			if board.visible[index] {
				log.Print("Guess already picked")
				return
			}
			if oldIndex >= 0 {
				if index == oldIndex {
					// This should be impossible, but let's be extra safe.
					log.Print("Guess already picked last time")
					return
				}
				board.visible[index] = true
				if board.nums[index] == board.nums[oldIndex] {
					// Correct.
					boardForResp = board.forResp()
					foundNum++
					if foundNum*2 == BoardSize {
						done = true
						message = fmt.Sprintf("You win! Flag: %s", flag)
					}
				} else {
					// Wrong. But still reveal the new guess in this response. The js will
					// hide it after a second. But after this response, hide it in future
					// responses.
					boardForResp = board.forResp()
					board.visible[index] = false
					board.visible[oldIndex] = false
					clear = [][]int{
						{guessBody.X, guessBody.Y},
						{oldIndex % BoardWidth, oldIndex / BoardWidth},
					}
				}
				oldIndex = -1
			} else {
				board.visible[index] = true
				boardForResp = board.forResp()
				oldIndex = index
			}
			turnsUsed++
			if turnsUsed >= maxTurns {
				done = true
				if message == "" {
					// If the user won on the last turn, don't give a turns exausted
					// message, give the flag message.
					message = "Turns exhaused"
				}
			}
			if turnDeadline.Before(time.Now()) {
				done = true
				// If the user won, but was slow on the last turn, don't display
				// the flag, overwrite it with this message.
				message = "You ran out of time"
			}
			turnDeadline = time.Now().Add(maxTurnTime)
		default:
			log.Printf("Bad op [%s]", req.Op)
			return
		}

		if err := conn.SetWriteDeadline(turnDeadline.Add(5 * time.Second)); err != nil {
			log.Printf("Couldn't set write deadline: %v", err)
			return
		}
		resp := Resp{
			Width:       BoardWidth,
			Board:       boardForResp,
			MaxTurns:    maxTurns,
			MaxTurnTime: maxTurnTime.Seconds(),
			TurnsUsed:   turnsUsed,
			Done:        done,
			Message:     message,
			Clear:       clear,
		}
		if err := conn.WriteJSON(resp); err != nil {
			log.Printf("Couldn't write json: %v", err)
			return
		}
	}
}
