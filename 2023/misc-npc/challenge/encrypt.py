# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This file encrypts a given file using a generated, easy to remember password.

Additionally, it generates a hint in case you forgot the password.
"""

import dataclasses
import re
import secrets
import sys

from pyrage import passphrase


def get_word_list():
  with open('USACONST.TXT', encoding='ISO8859') as f:
    text = f.read()
  return list(set(re.sub('[^a-z]', ' ', text.lower()).split()))


def generate_password(num_words):
  word_list = get_word_list()
  return ''.join(secrets.choice(word_list) for _ in range(num_words))


@dataclasses.dataclass
class Node:
  letter: str
  id: int


@dataclasses.dataclass
class Edge:
  a: Node
  b: Node


@dataclasses.dataclass
class Graph:
  nodes: list[Node]
  edges: list[Edge]


class IdGen:
  def __init__(self):
    self.ids = set()

  def generate_id(self):
    while True:
      new_id = secrets.randbelow(1024**3)
      if new_id not in self.ids:
        self.ids.add(new_id)
        return new_id


def generate_hint(password):
  random = secrets.SystemRandom()
  id_gen = IdGen()
  graph = Graph([],[])
  for letter in password:
    graph.nodes.append(Node(letter, id_gen.generate_id()))
  for a, b in zip(graph.nodes, graph.nodes[1:]):
    graph.edges.append(Edge(a, b))
  for _ in range(int(len(password)**1.3)):
    a, b = random.sample(graph.nodes, 2)
    graph.edges.append(Edge(a, b))
  random.shuffle(graph.nodes)
  random.shuffle(graph.edges)
  for edge in graph.edges:
    if random.random() % 2:
      edge.a, edge.b = edge.b, edge.a
  return graph

def write_hint(graph, out_file):
  out_file.write('graph {\n')
  for node in graph.nodes:
    out_file.write(f'    {node.id} [label={node.letter}];\n')
  for edge in graph.edges:
    out_file.write(f'    {edge.a.id} -- {edge.b.id};\n')
  out_file.write('}\n')


def encrypt(num_words, secret):
  password = generate_password(num_words)
  hint = generate_hint(password)
  with open('hint.dot', 'w') as hint_file:
    write_hint(hint, hint_file)
  filename = 'secret.age'
  with open(filename, 'wb') as f:
    f.write(passphrase.encrypt(secret, password))
  print(f'Your secret is now inside password-protected file {filename}.')
  print(f'Use the password {password} to access it.')
  print(
      'In case you forgot the password, maybe hint.dot will help your memory.')


if __name__ == '__main__':
  encrypt(num_words=int(sys.argv[1]), secret=sys.argv[2].encode('utf-8'))
