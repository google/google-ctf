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

#include <cstdio>
#include <iostream>
#include <string>
#include <cstring>
#include "convert_to_dfa.h"
#include "create_machine_code.h"
#include "run_regex.h"
#include "regex_to_nfa.h"

#define MAX_STORED_REGEXES   100

#define MAX_REGEX_LEN        512

void printNfa(NFA &nfa);
void printDfa(DFA &dfa);

int main() {
  std::vector<void *> regexes;
  std::string re;

  std::cout << "\n*****\t*****\t*****\n";
  std::cout
      << "\nREGEX FORMAT : \n"
      << "> Enclose every `concatenation` and `or` section by parentheses \n"
      << "> Enclose the entire regular expression with parentheses \n"
      << "> Use square brackets as a shortcut to `or` ranges.\n\n";

  std::cout << "For example : (a(b|c)[a-c]*) \n";

  while (true) {
    std::cout << "\n\nEnter a regular expression in the above mentioned format, "
              "or QUIT to quit.\n\n";
    std::cin >> re;
    if (re == "QUIT") {
      break;
    }

    if (re.length() > MAX_REGEX_LEN) {
      printf("Too long regex!\n");
      break;
    }

    NFA nfa;
    nfa = regex_to_nfa(re);

    DFA dfa = convertNfa(nfa);

    //    printNfa(nfa);
    //    printDfa(dfa);

    void *mem = createMachineCode(dfa);
    //printf ("%p\n", mem);
    if (regexes.size() >= MAX_STORED_REGEXES) {
      printf("Too many stored regexes\n");
      exit(0);
    }
    regexes.push_back(mem);
    printf("Your regex was saved as regex #%lu.\n", regexes.size() - 1);
    std::string action;
    std::cout << "Enter REGEX to create another regex, or TEST to test your "
                 "regexes.\n";
    std::cin >> action;
    if (action == "TEST") {
      std::string whichRegex;
      std::cout << "Which regex do you want to test? (zero-indexed)\n";
      std::cin >> whichRegex;
      void *regex = regexes.at(std::stoi(whichRegex));

      std::string toTest;
      while (true) {
        std::cout << "Enter a string to match against the regex, or QUIT to quit "
                  "and enter more regexes:\n\n";
        std::cin >> toTest;
        if (toTest == "QUIT") {
          break;
        }
        bool result = doesMatch(regex, toTest);
        printf("%s\n",
               result ? "The regex matches the string!" : "No match found.");
      }
    }
  }
  return 0;
}

void printNfa(NFA &nfa) {
  printf ("NFA %d %d %d\n", nfa.numStates, nfa.startState, nfa.finalState);
  for (auto t : nfa.transitions) {
    int s = t.symbol;
    if (s == -1) {
      printf ("%d %d EP\n", t.from, t.to);
    } else {
      printf ("%d %d %c\n", t.from, t.to, t.symbol);
    }
  }
}

void printDfa(DFA &dfa) {
  printf ("DFA %d %d\n", dfa.numStates, dfa.startState);
  for (auto i : dfa.finalStates) {
    printf ("%d ", i);
  }
  printf ("\n");
  for (auto t : dfa.transitions) {
    printf ("%d %d %c\n", t.from, t.to, t.symbol);
  }
}
