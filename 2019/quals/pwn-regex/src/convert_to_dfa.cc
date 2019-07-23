/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "convert_to_dfa.h"

#include <map>
#include <set>
#include <queue>

#define MAX_PROCESS 65534

typedef std::set<int> nfaSet;

/**
 * Follows repeatedly all epsilon transitions in a set of NFA states.
 */
void expandEpsilon(NFA &nfa, nfaSet& state) {
  nfaSet extraStates;
  bool changes = true;
  while (changes) {
    changes = false;
    for (auto t : nfa.transitions) {
      if (t.symbol != EPSILON) continue;
      if (state.find(t.from) == state.end()) continue;
      if (state.find(t.to) != state.end()) continue;
      state.insert(t.to);
      changes = true;
    }
  }
}

/**
 * For every NFA state in the set, follows all transitions for that character.
 */
nfaSet doTransition(NFA &nfa, nfaSet& state, int character) {
  nfaSet newSet;
  for (auto t : nfa.transitions) {
    if (t.symbol != character) continue;
    if (state.find(t.from) == state.end()) continue;
    newSet.insert(t.to);
  }
  return newSet;
}

DFA convertNfa(NFA &nfa) {
  std::map<nfaSet, int> nfaToDfa;
  std::queue<nfaSet> toProcess;
  DFA dfa;


  nfaSet startState;
  startState.insert(nfa.startState);
  expandEpsilon(nfa, startState);

  nfaToDfa[startState] = 0;
  if (startState.find(nfa.finalState) != startState.end()) {
    dfa.finalStates.push_back(0);
  }
  dfa.startState = 0;
  toProcess.push(startState);

  int totalStates = 1;
  while (!toProcess.empty() && totalStates < MAX_PROCESS) {
    nfaSet cur = toProcess.front();
    toProcess.pop();
    int curNum = nfaToDfa.at(cur);
    for (int i = 1; i <= 255; i++) {
      nfaSet newState = doTransition(nfa, cur, i);
      if (newState.empty()) continue;
      expandEpsilon(nfa, newState);
      if (nfaToDfa.find(newState) == nfaToDfa.end()) {
        nfaToDfa[newState] = totalStates;
        if (newState.find(nfa.finalState) != newState.end()) {
          dfa.finalStates.push_back(totalStates);
        }
        totalStates++;
        toProcess.push(newState);
      }
      int stateNum = nfaToDfa.at(newState);
      dfa.transitions.push_back({curNum, stateNum, i});
    }
  }
  if (totalStates >= MAX_PROCESS) {
    printf ("Too many states!\n");
    exit(0);
  }
  dfa.numStates = totalStates;
  return dfa;
}
