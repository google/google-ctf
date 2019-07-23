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

// Binary estimate estimates how many guesses are needed to uniquely identify
// a board layout. It doesn't use real board layouts, but instead layouts that
// are distributed similarly. It gives the fail probability for each number
// of guesses.
// This program can be used both as a tool to identify a good solution
// algorithm, as well as a tool to generate a good boardSize and numNonZeroBits
// when creating the challenge.
package main

import (
	"crypto/md5"
	"encoding/binary"
	"log"
	"math/rand"
)

const (
	boardSize      = 56
	numNonZeroBits = 17
	numSeeds       = 1 << numNonZeroBits
)

func main() {
	r := rand.New(rand.NewSource(0))
	slices := make([][]byte, numSeeds)

	for i := 0; i < numSeeds; i++ {
		s := make([]byte, boardSize)
		slices[i] = s
		for j := 0; j < boardSize; j++ {
			s[j] = byte(j / 2)
		}
		r.Shuffle(boardSize, func(a, b int) {
			s[a], s[b] = s[b], s[a]
		})
	}
	for i := 0; i < 20; i++ {
		m := map[uint64]struct{}{}
		for _, s := range slices {
			// Instead of comparing the entire first i elements of the board layouts,
			// we just compare the first 8 bytes of the md5 hash of the first i bytes
			// of the board layouts.
			md5h := md5.Sum(s[:i])
			v64 := binary.LittleEndian.Uint64(md5h[:])
			m[v64] = struct{}{}
		}
		numDupes := numSeeds - len(m)
		rDupes := float64(numDupes) / float64(numSeeds)
		rInitials := 1 - rDupes
		log.Printf("i %2d numDupes %6d rDupes %f rInitials %f",
			i, numDupes, rDupes, rInitials)
	}
}
