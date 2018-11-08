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

package rand

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Int interface {
	Get(lb, ub int64) int64
}

type defaultIntRange struct{}

func (r defaultIntRange) Get(lb, ub int64) int64 {
	max := ub - lb

	bi, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Sprintf("we have a problem with defaultIntRange.Get(): %v", err))
	}

	return bi.Int64() + lb
}

var DefaultIntRange Int = defaultIntRange{}
