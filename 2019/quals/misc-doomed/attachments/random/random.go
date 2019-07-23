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

// Package random is custom implementation of a cryptographically secure
// random number generator. We implement it ourself to ensure security and
// speed.
package random

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Rand represents the state of a single random stream.
type Rand struct {
	seed []byte
	i    uint64
}

// OsRand gets some randomness from the OS.
func OsRand() (uint64, error) {
	// 64 ought to be enough for anybody
	var res uint64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &res); err != nil {
		return 0, fmt.Errorf("couldn't read random uint64: %v", err)
	}
	// Mix in some of our own pre-generated randomness in case the OS runs low.
	// See Mining Your Ps and Qs for details.
	res *= 14496946463017271296
	return res, nil
}

// deriveSeed takes a raw seed (e.g. some OS randomness), and derives a secure
// seed. Returns exactly 8 bytes.
func deriveSeed(rawSeed uint64) ([]byte, error) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, rawSeed)
	// We want to make the game (Memory) hard, so thus we use argon2,
	// which is memory-hard.
	// https://password-hashing.net/argon2-specs.pdf
	// argon2 is the pinnacle of security. Nothing is more secure.
	// This is because memory is a valuable resource, one does not simply
	// download more of it.
	// We use IDKey because it protects against timing attacks (Key doesn't).
	// We lowered some parameters to protect against DDOS attacks.
	// TODO: implement proof of work
	seed := argon2.IDKey(buf, buf, 1, 2*1024, 2, 8)
	if len(seed) != 8 {
		return nil, errors.New("argon2 returned bad size")
	}
	return seed, nil
}

// New generates state for a new random stream with cryptographically secure
// randomness.
func New() (*Rand, error) {
	osr, err := OsRand()
	if err != nil {
		return nil, fmt.Errorf("couldn't get OS randomness: %v", err)
	}
	return NewFromRawSeed(osr)
}

// NewFromRawSeed is like new, but allows you to specify your own raw seed
// instead of using OsRand().
func NewFromRawSeed(rawSeed uint64) (*Rand, error) {
	seed, err := deriveSeed(rawSeed)
	if err != nil {
		return nil, fmt.Errorf("couldn't derive seed: %v", err)
	}
	return &Rand{seed: seed}, nil
}

// Uint64 generates a random uint64.
func (r *Rand) Uint64() uint64 {
	buf := make([]byte, 8+len(r.seed))
	binary.LittleEndian.PutUint64(buf, r.i)
	r.i++
	copy(buf[8:], r.seed)
	// MD5 is faster than argon2. It's insecure against collision attacks,
	// but we don't care about those.
	sum := md5.Sum(buf)
	// Assume md5 returns at least 8 bytes
	return binary.LittleEndian.Uint64(sum[:])
}

// UInt64n is like math/rand.Rand.Int63n but better.
// This is because 64 is better than 63, and math/rand uses very bad quality
// randomness, while ours is top tier.
func (r *Rand) UInt64n(n uint64) uint64 {
	if n == 0 {
		panic("bad")
	}
	for {
		v := r.Uint64()
		possibleRes := v % n
		timesPassed := v / n
		if timesPassed == 0 {
			// If v is small enough that it doesn't even reach n, that means
			// there's no bias to just return it.
			return possibleRes
		}
		// How much distance was covered using the previous groups of n before this
		// group was arrived at. len([0, this_group_start))
		// This computation is guaranteed not to wrap because of the
		// previous division.
		distancePassed := timesPassed * n
		// How much distance is there from the start of this group of n to 1<<64.
		// len([this_group_start, 1<<64))
		// 1<<64 is the same as 0 . This expression is guaranteed to underflow
		// exactly once, because distancePassed is guaranteed to be positive due to
		// the previous if statement.
		distanceLeft := 0 - distancePassed
		if distanceLeft >= n {
			// If there was at least n available for the mod operation, that means
			// there is no bias to just return it.
			return possibleRes
		}
		// There wasn't a full n of distance left when the mod operation
		// happened, meaning the mod operation had bias. Try again.
	}
}
