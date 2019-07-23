/*
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "regex_to_nfa.h"

#include <iostream>
#include <set>
#include <stack>
#include <string>
#include <vector>

/*
 * Changes made: Implicit concatenation, character sets, made it all static
 * functions.
 */

NFA concat(NFA a, NFA b) {
  NFA result;
  result.numStates = a.numStates + b.numStates;

  for (auto new_trans : a.transitions) {
    result.transitions.push_back({new_trans.from, new_trans.to, new_trans.symbol});
  }

  result.transitions.push_back({a.finalState, a.numStates, EPSILON});

  for (auto new_trans : b.transitions) {
    result.transitions.push_back({new_trans.from + a.numStates, new_trans.to + a.numStates, new_trans.symbol});
  }

  result.finalState = a.numStates + b.numStates - 1;

  return result;
}

NFA kleene(NFA a) {
  NFA result;

  result.numStates = a.numStates + 2;
  result.transitions.push_back({0, 1, EPSILON});

  for (auto new_trans : a.transitions) {
    result.transitions.push_back({new_trans.from + 1, new_trans.to + 1, new_trans.symbol});
  }

  result.transitions.push_back({a.numStates, a.numStates + 1, EPSILON});
  result.transitions.push_back({a.numStates, 1, EPSILON});
  result.transitions.push_back({0, a.numStates + 1, EPSILON});

  result.finalState = a.numStates + 1;

  return result;
}

NFA or_selection(std::vector<NFA> selections, int no_of_selections) {
  NFA result;
  int vertex_count = 2;
  int i;
  NFA med;

  for (i = 0; i < no_of_selections; i++) {
    vertex_count += selections.at(i).numStates;
  }

  result.numStates = vertex_count;

  int adder_track = 1;

  for (i = 0; i < no_of_selections; i++) {
    result.transitions.push_back({0, adder_track, EPSILON});
    med = selections.at(i);
    for (auto new_trans : med.transitions) {
      result.transitions.push_back({new_trans.from + adder_track, new_trans.to + adder_track, new_trans.symbol});
    }
    adder_track += med.numStates;

    result.transitions.push_back({adder_track - 1, vertex_count - 1, EPSILON});
  }

  result.finalState = vertex_count - 1;

  return result;
}

NFA base_nfa(int cur_sym) {
  NFA *new_sym = new NFA();
  new_sym->numStates = 2;
  new_sym->transitions.push_back({0, 1, cur_sym});
  new_sym->finalState = 1;
  return *new_sym;
}

bool isNormalCharacter(char cur_sym) {
  return cur_sym != '(' && cur_sym != ')' && cur_sym != '*' && cur_sym != '|' &&
      cur_sym != '.' && cur_sym != '[' && cur_sym != ']';
}

NFA regex_to_nfa(std::string re) {
  std::stack<int> operators;
  std::stack<NFA> operands;
  char op_sym;
  int op_count;
  char cur_sym;

  for (std::string::iterator it = re.begin(); it != re.end(); ++it) {
    cur_sym = *it;
    if (isNormalCharacter(cur_sym)) {
        operands.push(base_nfa(cur_sym));
        if (isNormalCharacter(*(it+1)) || *(it+1) == '(' || *(it+1) == '[') {
          operators.push('.');
        }
    } else if (cur_sym == '[') {
      // Is this a bad idea? Yes, yes it is.
      std::vector<int> numbers_to_or;
      while (*(++it) != ']') {
        if (*it == '-') {
          ++it;
          int or_from = numbers_to_or.back();
          numbers_to_or.pop_back();
          int or_to = *it;
          for (int i = or_from; i <= or_to; i++) {
            numbers_to_or.push_back(i);
          }
        } else {
          numbers_to_or.push_back(*it);
        }
      }
      std::vector<NFA> nfas_to_or;
      for (auto i : numbers_to_or) {
        nfas_to_or.push_back(base_nfa(i));
      }
      operands.push(or_selection(nfas_to_or, nfas_to_or.size()));
      if (isNormalCharacter(*(it+1)) || *(it+1) == '(' || *(it+1) == '[') {
        operators.push('.');
      }
    } else {
      if (cur_sym == '*') {
        NFA star_sym = operands.top();
        operands.pop();
        operands.push(kleene(star_sym));
        if (isNormalCharacter(*(it+1)) || *(it+1) == '(' || *(it+1) == '[') {
        operators.push('.');
        }
      } else if (cur_sym == '.' || cur_sym == '|' || cur_sym == '(') {
        operators.push(cur_sym);
      } else { // Found a ')'
        op_count = 0;
        op_sym = operators.top();
        if (op_sym == '(') continue;
        do {
          operators.pop();
          op_count++;
        } while (operators.top() != '(');
        operators.pop();
        NFA op1;
        NFA op2;
        std::vector<NFA> selections;
        if (op_sym == '.') {
          for (int i = 0; i < op_count; i++) {
            op2 = operands.top();
            operands.pop();
            op1 = operands.top();
            operands.pop();
            operands.push(concat(op1, op2));
          }
        } else if (op_sym == '|') {
          selections.assign(op_count + 1, NFA());
          int tracker = op_count;
          for (int i = 0; i < op_count + 1; i++) {
            selections.at(tracker) = operands.top();
            tracker--;
            operands.pop();
          }
          operands.push(or_selection(selections, op_count + 1));
        } else {
        }
        if (it+1 != re.end() && (isNormalCharacter(*(it+1)) || *(it+1) == '(' || *(it+1) == '[')) {
          operators.push('.');
        }
      }
    }
  }

  return operands.top();
}
