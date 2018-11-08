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

package message

import (
	"fmt"
	"sort"
)

type SingleWorkMessage struct {
	From  int `json:"from"`
	To    int `json:"to"`
	Round int `json:"round"`
}

func singleWorkLess(lhs, rhs *SingleWorkMessage) bool {
	if lhs.Round < rhs.Round {
		return true
	} else if lhs.Round > rhs.Round {
		return false
	}

	if lhs.From < rhs.From {
		return true
	} else if lhs.From > rhs.From {
		return false
	}

	if lhs.To < rhs.To {
		return true
	} else if lhs.To > rhs.To {
		return false
	}

	/* WE DONT CARE ABOUT THE CONTENT */
	return false
}

func WorkCmp(w []*SingleWorkMessage) func(int, int) bool {
	return func(i, j int) bool {
		return singleWorkLess(w[i], w[j])
	}
}

func DiffWorks(lhs, rhs []*SingleWorkMessage) string {
	if len(lhs) != len(rhs) {
		return fmt.Sprintf("Different lenghts: %v != %v", len(lhs), len(rhs))
	}
	sort.Slice(lhs, WorkCmp(lhs))
	sort.Slice(rhs, WorkCmp(rhs))
	for i := range lhs {
		if !(!singleWorkLess(lhs[i], rhs[i]) && !singleWorkLess(rhs[i], lhs[i])) {
			return fmt.Sprintf("Elements differ at position %v:\n%v\n\n%v", i, lhs[i], rhs[i])
		}
	}
	return ""
}
