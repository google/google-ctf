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

package system

import (
	"endpoint"
	"math/rand"
)

type edge struct {
	u int
	v int
}
type RandDenseNetworkFactory struct {
	Size int
}

func (f *RandDenseNetworkFactory) Network() endpoint.Network {
	if f.Size < 5 {
		panic("the initial graph size is a bit too small, come on, make it at least 5")
	}

	var edges []edge
	for i := 1; i <= f.Size; i++ {
		for j := i + 1; j <= f.Size; j++ {
			edges = append(edges, edge{i, j})
		}
	}
	rand.Shuffle(len(edges), func(i, j int) {
		edges[i], edges[j] = edges[j], edges[i]
	})

	// Keeping the graph very dense.
	edges = edges[:len(edges)-f.Size]

	g := NewGraph(f.Size)
	for _, e := range edges {
		g.InsertEdge(e.u, e.v)
	}
	return g
}

type Graph struct {
	e map[int]map[int]bool
}

func NewGraph(size int) *Graph {
	m := map[int]map[int]bool{}
	for i := 1; i <= size; i++ {
		m[i] = map[int]bool{}
	}
	return &Graph{m}
}

var _ endpoint.Network = (*Graph)(nil)

// insertDirectedEdge inserts a directed edge to the graph.
// WARNING: This will leave the graph in an invalid state
// if it's not called for both directions!
func (g *Graph) insertDirectedEdge(a, b int) {
	if g.e[a] == nil {
		g.e[a] = map[int]bool{b: true}
	} else {
		g.e[a][b] = true
	}
}

func (g *Graph) HasEdge(u, v int) bool {
	return g.e[u][v]
}

// removeDirectedEdge removes a directed edge from the graph.
// WARNING: This will leave the graph in an invalid state
// if it's not called for both directions!
func (g *Graph) removeDirectedEdge(a, b int) {
	delete(g.e[a], b)
}

func (g *Graph) InsertEdge(a, b int) {
	g.insertDirectedEdge(a, b)
	g.insertDirectedEdge(b, a)
}

func (g *Graph) Size() int {
	return len(g.e)
}

func (g *Graph) Neighbours(node int) []int {
	var n []int
	for k, v := range g.e[node] {
		if v {
			n = append(n, k)
		}
	}
	return n
}

func (g *Graph) Nodes() []int {
	var ns []int
	for k := range g.e {
		ns = append(ns, k)
	}
	return ns
}
