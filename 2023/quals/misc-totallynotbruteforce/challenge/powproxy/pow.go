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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

const (
	version = "s"
)

var (
	modulus  = new(big.Int)
	chalsize = new(big.Int)
	one      = big.NewInt(1)
	two      = big.NewInt(2)
)

func init() {
	modulus.Set(two)
	modulus.Exp(modulus, big.NewInt(1279), nil)
	modulus.Sub(modulus, one)
	chalsize.Set(two)
	chalsize.Exp(chalsize, big.NewInt(128), nil)
}

func slothSquare(x *big.Int, diff int, mod *big.Int) *big.Int {
	y := new(big.Int)
	y.Set(x)
	for i := 0; i < diff; i++ {
		y.Exp(y.Xor(y, one), two, mod)
	}
	return y
}

func slothRoot(x *big.Int, diff int, mod *big.Int) *big.Int {
	exp := new(big.Int)
	exp.Set(mod)
	exp.Add(exp, one)
	exp.Div(exp, big.NewInt(4))

	y := new(big.Int)
	y.Set(x)
	for i := 0; i < diff; i++ {
		y.Xor(y.Exp(y, exp, mod), one)
	}
	return y
}

type Solution struct {
	*big.Int
}

func DecodeSolution(solution string) (*Solution, error) {
	parts := strings.SplitN(solution, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("Invalid solution")
	}

	if parts[0] != version {
		return nil, errors.New("Invalid solution version")
	}

	solutionData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	s := new(big.Int)
	s.SetBytes(solutionData)

	return &Solution{s}, nil
}

func (s *Solution) String() string {
	encodedS := base64.StdEncoding.EncodeToString(s.Bytes())
	return version + "." + encodedS
}

type Challenge struct {
	difficulty int
	x          *big.Int
}

func DecodeChallenge(challenge string) (*Challenge, error) {
	parts := strings.SplitN(challenge, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("Invalid challenge")
	}

	if parts[0] != version {
		return nil, errors.New("Invalid challenge version")
	}

	difficultyData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	difficulty := new(big.Int)
	difficulty.SetBytes(difficultyData)

	xData, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	x := new(big.Int)
	x.SetBytes(xData)

	return &Challenge{int(difficulty.Int64()), x}, nil
}

func NewChallenge(difficulty int) (*Challenge, error) {
	x, err := rand.Int(rand.Reader, chalsize)
	if err != nil {
		return nil, err
	}

	return &Challenge{difficulty, x}, nil
}

func (c *Challenge) String() string {
	encodedDifficulty := base64.StdEncoding.EncodeToString(big.NewInt(int64(c.difficulty)).Bytes())
	encodedX := base64.StdEncoding.EncodeToString(c.x.Bytes())
	return version + "." + encodedDifficulty + "." + encodedX
}

func (c *Challenge) Verify(s *Solution) bool {
	res := slothSquare(s.Int, c.difficulty, modulus)
	mod := new(big.Int)
	mod.Set(modulus)
	mod.Sub(mod, res)
	return c.x.Cmp(res) == 0 || c.x.Cmp(mod) == 0
}

func (c *Challenge) Solve() *Solution {
	return &Solution{slothRoot(c.x, c.difficulty, modulus)}
}
