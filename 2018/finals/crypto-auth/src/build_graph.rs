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

use rand::distributions::Distribution;

type NodeType = (usize, usize);
pub type GraphType = petgraph::graphmap::UnGraphMap<NodeType, usize>;

pub fn large_graph(grid_size: usize, graph_size: usize, mask_size: usize) -> GraphType {
    let mut rng = rand::thread_rng();
    let mut grid = vec![vec![false; 2 * grid_size]; 2 * grid_size];
    let directions = rand::distributions::Uniform::from(0.0..1.0);
    grid[grid_size][grid_size] = true;
    let mut hbounds = (grid_size, grid_size);
    let mut vbounds = (grid_size, grid_size);
    for _ in 0..graph_size {
        let vertical = directions.sample(&mut rng) > 0.5;
        let positive = directions.sample(&mut rng) > 0.5;
        if vertical {
            let x = rand::distributions::Uniform::from(hbounds.0..hbounds.1 + 1).sample(&mut rng);
            let mut prev = if positive { 2 * grid_size - 1 } else { 0 };
            for offset in 0..2 * grid_size {
                let y = if positive {
                    2 * grid_size - offset - 1
                } else {
                    offset
                };
                if grid[x][y] {
                    if prev > vbounds.1 {
                        vbounds.1 = prev;
                    } else if y < vbounds.0 {
                        vbounds.0 = prev;
                    }
                    grid[x][prev] = true;
                    break;
                }
                prev = y;
            }
        } else {
            let y = rand::distributions::Uniform::from(vbounds.0..vbounds.1 + 1).sample(&mut rng);
            let mut prev = if positive { 2 * grid_size - 1 } else { 0 };
            for offset in 0..2 * grid_size {
                let x = if positive {
                    2 * grid_size - offset - 1
                } else {
                    offset
                };
                if grid[x][y] {
                    if prev > hbounds.1 {
                        hbounds.1 = prev;
                    } else if y < hbounds.0 {
                        hbounds.0 = prev;
                    }
                    grid[prev][y] = true;
                    break;
                }
                prev = x;
            }
        }
    }

    let mut gg = vec![vec![false; 2 * grid_size]; 2 * grid_size];
    for x in mask_size..2 * grid_size - mask_size {
        for y in mask_size..2 * grid_size - mask_size {
            let mut bit = false;
            for i in 0..mask_size * 2 + 1 {
                for j in 0..mask_size * 2 + 1 {
                    bit = bit || grid[x + i - mask_size][y + j - mask_size];
                }
            }
            gg[x][y] = bit;
        }
    }

    let mut graph = GraphType::new();
    for x in 0..2 * grid_size {
        for y in 0..2 * grid_size {
            if gg[x][y] && gg[x + 1][y + 0] {
                graph.add_edge((x, y), (x + 1, y + 0), 1);
            }
            if gg[x][y] && gg[x + 0][y + 1] {
                graph.add_edge((x, y), (x + 0, y + 1), 1);
            }
            if gg[x][y] && gg[x - 1][y + 0] {
                graph.add_edge((x, y), (x - 1, y + 0), 1);
            }
            if gg[x][y] && gg[x + 0][y - 1] {
                graph.add_edge((x, y), (x + 0, y - 1), 1);
            }
        }
    }

    // for x in 0..2 * grid_size {
    //     print!("{}: ", x);
    //     for y in 0..2 * grid_size {
    //         print!("{}", if gg[x][y] { "o" } else { "." });
    //     }
    //     println!("");
    // }
    // println!("!! {:?}", graph);
    return graph;
}

