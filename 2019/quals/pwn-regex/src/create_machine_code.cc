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

#include "create_machine_code.h"
#include "stubs.h"

#include <cstring>
#include <sys/mman.h>
#include <algorithm>

void* getMemory(int size) {
  void *ptr = mmap(0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ptr == NULL) {
    exit(1);
  }
  return ptr;
}

void writeIntoMemory(DFA &dfa, int nodeNum, char *mem) {
  int startPlace = nodeNum * stub1Len;
  memcpy(mem + startPlace, stub1, stub1Len);
  for (int i = 0; i < 256; i++) {
    ((short*)(&mem[startPlace]))[i] = dfa.numStates - nodeNum + 1;
  }
  if (std::find(dfa.finalStates.begin(), dfa.finalStates.end(), nodeNum) != dfa.finalStates.end()) {
    ((short*)(&mem[startPlace]))[0] = dfa.numStates - nodeNum;
  }
  for (auto t : dfa.transitions) {
    if (t.from != nodeNum) continue;
    short offset = t.to - t.from;
    ((short*)(&mem[startPlace]))[t.symbol] = offset;
  }
}

void* createMachineCode(DFA &dfa) {
  int totalSize = dfa.numStates * stub1Len + stub2Len + stub3Len + stub4Len;
  void* regexSpace = getMemory(totalSize);
  memcpy(regexSpace, stub4, stub4Len);
  char *newPlace = &((char*) regexSpace)[stub4Len];
  for (int i = 0; i < dfa.numStates; i++) {
    writeIntoMemory(dfa, i, newPlace);
  }
  memcpy(&newPlace[dfa.numStates * stub1Len], stub2, stub2Len);
  memcpy(&newPlace[(dfa.numStates + 1) * stub1Len], stub3, stub3Len);
  return regexSpace;
}

