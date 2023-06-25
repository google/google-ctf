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

"""A more sophisticated attempt at cracking the password.

It uses the fact that the password was generated from a given dictionary and it
also looks at the hint - it tries to get both the hamiltonian path and the
password at the same time.
"""
import collections
import heapq
import pyrage
from pyrage import passphrase
import re


def get_word_list():
  with open('USACONST.TXT', encoding='ISO8859') as f:
    text = f.read()
  return list(set(re.sub('[^a-z]', ' ', text.lower()).split()))


Node = collections.namedtuple('Node', ['id', 'label'])


class TrieNode:
  def __init__(self):
    self.word = ''
    self.edges = collections.defaultdict(TrieNode)


def get_hint():
  nodes = {}
  edges = {}
  with open('hint.dot') as f:
    for line in f.readlines():
      if (match := re.search(r'([0-9]+) \[label=([a-z])\]', line)):
        node = Node(int(match.group(1)), match.group(2))
        nodes[node.id] = node
        edges[node] = collections.defaultdict(list)
      if (match := re.search('([0-9]+) -- ([0-9]+)', line)):
        a = nodes[int(match.group(1))]
        b = nodes[int(match.group(2))]
        edges[a][b.label].append(b)
        edges[b][a.label].append(a)
  root = Node(-1, '')
  edges[root] = collections.defaultdict(list)
  for node in nodes.values():
    edges[root][node.label].append(node)
  return root, edges

def get_signature(text):
  signature = [0] * 26
  for c in text:
    signature[ord(c)-ord('a')] += 1
  return tuple(signature)


def promising_signature(signature, target_signature):
  for s, t in zip(signature, target_signature):
    if s > t:
      return False
  return sum(signature) <= sum(target_signature)

def get_trie(words):
  root = TrieNode()
  for word in sorted(words, key=len, reverse=True):
    node = root
    for c in word:
      node = node.edges[c]
    node.word = word
  return root


def walk_graph(node, edges, trie):
  visited = {(node, 0, id(trie))}
  queue = [(node, 0, trie)]
  while queue:
    current_node, distance, current_trie = queue.pop(0)
    if current_trie.word:
      yield current_trie.word, current_node
    for c, new_trie in current_trie.edges.items():
      for new_node in edges[current_node][c]:
        if (new_node, distance+1, id(new_trie)) not in visited:
          visited.add((new_node, distance+1, id(new_trie)))
          queue.append((new_node, distance+1, new_trie))


def passwords(words, hint):
  trie = get_trie(words)
  root, edges = hint
  attempts = [(0, '', root)]
  checked = {''}
  previous_attempts = {('', root)}
  target_signature = get_signature(''.join(n.label for n in edges))
  while attempts:
    words, attempt, node = heapq.heappop(attempts)
    if len(attempt) == len(edges) - 1 and attempt not in checked:
      checked.add(attempt)
      yield attempt
    if promising_signature(get_signature(attempt), target_signature):
      new_attempts = {
          (attempt + word, new_node)
          for (word, new_node) in walk_graph(node, edges, trie)
          if (attempt + word, new_node) not in previous_attempts
      }
      previous_attempts.update(new_attempts)
      for new_attempt, new_node in new_attempts:
        if promising_signature(get_signature(new_attempt), target_signature):
          heapq.heappush(attempts, (words+1, new_attempt, new_node))


def generate_passwords():
  words = get_word_list()
  hint = get_hint()
  for password in passwords(words, hint):
    yield ''.join(password)


def decrypt(cyphertext):
  for i, password in enumerate(generate_passwords()):
    try:
      print(f'Trying {i}th password: {password}')
      content = passphrase.decrypt(cyphertext, password)
      print(f'\nThe password was {password}')
      return content
    except (RuntimeError, pyrage.DecryptError):
      continue


if __name__ == '__main__':
  secret = decrypt(open('secret.age', 'rb').read())
  print(f'The secret is: {secret.decode("utf-8")}')
