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

package endpoint

import "message"

type SystemAdmin interface {
	// Work returns proof-of-work for a given magic number.
	Work(magic int64) []*message.SingleWorkMessage

	// ChangeNetwork changes the system's network.
	ChangeNetwork(network Network)

	Network() Network
}

type Network interface {
	Neighbours(u int) []int
	HasEdge(u, v int) bool
	Size() int
}
