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

// Binary gen generates the boards.bin file used to solve the Doomed to Repeat
// It challenge. The boards.bin file contains all 1<<17 possible board layouts.
package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"memory/game"
	"memory/random"
)

const (
	// https://www.wolframalpha.com/input/?i=14496946463017271296
	// It's divisible by 1<<47 .
	numZeroBits    = 47
	numNonZeroBits = 64 - numZeroBits // 17
	numSeeds       = 1 << numNonZeroBits
)

func main() {
	output := make([]byte, game.BoardSize*numSeeds)
	for seedi := uint64(0); seedi < numSeeds; seedi++ {
		if seedi%(1<<12) == 0 {
			fmt.Printf("seedi %d\n", seedi)
		}
		board := output[seedi*game.BoardSize : (seedi+1)*game.BoardSize]
		osRand := seedi << numZeroBits
		r, err := random.NewFromRawSeed(osRand)
		if err != nil {
			log.Fatalf("Couldn't create Rand: %v", err)
		}
		for i, _ := range board {
			board[i] = byte(i / 2)
		}
		// https://github.com/golang/go/wiki/SliceTricks#shuffling
		for i := game.BoardSize - 1; i > 0; i-- {
			j := r.UInt64n(uint64(i) + 1)
			board[i], board[j] = board[j], board[i]
		}
	}
	if err := ioutil.WriteFile("boards.bin", output, 0600); err != nil {
		log.Fatalf("Couldn't write file: %v", err)
	}
}
