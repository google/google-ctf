// Copyright 2018 Google LLC
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
//

extern crate petgraph;
extern crate rand;

mod build_graph;

use petgraph::dot::{Config, Dot};
use rand::Rng;
use std::io::BufRead;
use std::io::Read;

type FuzzGraph = petgraph::graphmap::UnGraphMap<usize, ()>;

fn fuzz_graph(graph: build_graph::GraphType) -> FuzzGraph {
    let mut edges = Vec::new();
    for (u, v, _) in graph.all_edges() {
        edges.push((
            u.0 * graph.node_count() + u.1,
            v.0 * graph.node_count() + v.1,
            (),
        ));
    }
    let mut output = petgraph::graphmap::UnGraphMap::new();
    rand::thread_rng().shuffle(&mut edges);
    for (u, v, e) in edges {
        output.add_edge(u, v, e);
    }
    output
}

fn read_flag() -> String {
    let mut f = std::fs::File::open("flag.txt").expect("failed to open flag file");
    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("failed to read flag");
    contents
}

fn check_existence(graph: &mut FuzzGraph, nodes: &Vec<usize>, a: usize, b: usize) {
    match graph.remove_edge(nodes[a], nodes[b]) {
        Some(_) => {}
        None => {
            println!("Edge {} -- {} does not exist", nodes[a], nodes[b]);
            panic!("Edge {} -- {} does not exist", nodes[a], nodes[b]);
        }
    }
}

fn main() {
    let graph = build_graph::large_graph(30, 110, 1);
    let mut fuzzy = fuzz_graph(graph);
    {
        let p0 = Dot::with_config(&fuzzy, &[Config::EdgeNoLabel]);
        print!("{:?}", p0);
    }
    println!("There's your graph, pocket. Now give me a comma separated list that describe a hamiltonian cycle.");
    println!("Remember to use labels to identify the nodes.");
    println!("For example: for a K3 graph with labels ['10', '20', '30'], give 10, 20, 30, 10\\n.");
    let stdin = std::io::stdin();
    let handle = stdin.lock();
    let nodes: Vec<usize> = handle
        .lines()
        .next()
        .unwrap()
        .unwrap()
        .trim()
        .split(",")
        .map(|x| x.trim().parse().expect("not a number"))
        .collect();
    if nodes.len() != fuzzy.node_count() + 1 {
        println!("The cycle must have size |N| + 1");
        return;
    }
    let mut visited = std::collections::HashSet::new();
    for i in 0..nodes.len() - 1 {
        visited.insert(nodes[i]);
        check_existence(&mut fuzzy, &nodes, i, i + 1);
    }
    if visited.len() != fuzzy.node_count() {
        println!("The cycle doesn't go over all nodes.");
        return;
    }
    println!("Good job, here's the flag: {}", read_flag());
}
