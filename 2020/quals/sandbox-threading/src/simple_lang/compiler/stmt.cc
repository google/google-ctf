// Copyright 2020 Google LLC
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

// Author: Ian Eldred Pudney
#include "stmt.h"

#include "expr.h"
#include "type.h"

namespace ast {
void stmt_block::emit(ostream& os) {
  os << "{\n";
  for (auto& child : children) {
    cast<stmt*>(child.get())->emit(os);
  }
  os << "}\n";
}
void expr_stmt::emit(ostream& os) {
  assert(children.size() == 1);
  cast<expr*>(children[0].get())->emit(os);
  os << ";\n";
}
void assign_stmt::emit(ostream& os) {
  assert(children.size() == 2);
  auto* left = cast<left_expr*>(children[0].get());
  assert(left);  // Expression not permitted on left-hand side of assignment.
  expr* param = cast<expr*>(children[1].get());
  left->emit_left(os, param);
  os << ";\n";
}

void return_stmt::emit(ostream& os) {
  os << "return (";
  cast<expr*>(children[0].get())->emit(os);
  os << ");\n";
}
void if_stmt::emit(ostream& os) {
  os << "if (";
  cast<expr*>(children[0].get())->emit(os);
  os << ") {\n";
  cast<stmt*>(children[1].get())->emit(os);
  os << "}\n";
}
void while_stmt::emit(ostream& os) {
  os << "while (";
  cast<expr*>(children[0].get())->emit(os);
  os << ") {\n";
  cast<stmt*>(children[1].get())->emit(os);
  os << "}\n";
}
void var_decl::emit(ostream& os) {
  assert(children.size() == 2 || children.size() == 3);
  cast<type*>(children[0].get())->emit(os);
  os << " ";
  cast<ident*>(children[1].get())->emit(os);

  // initializer
  if (children.size() == 3) {
    os << " = ";
    cast<expr*>(children[2].get())->emit(os);
  }

  os << ";\n";
}
void typed_def_stmt::emit(ostream& os) {
  assert(children.size() == 4);
  // Return type
  cast<type*>(children[0].get())->emit(os);
  os << " ";

  // Guarantee no inlining, makes debugging easier
  os << "__attribute__ ((noinline)) ";

  // Function name
  cast<ident*>(children[1].get())->emit(os);
  os << "(";

  // Arguments
  cast<typed_arg_decl_list*>(children[2].get())->emit(os);
  os << ") {\n";

  // Statement
  cast<stmt*>(children[3].get())->emit(os);
  os << "}\n";
}

void typed_arg_decl_list::emit(ostream& os) {
  assert(children.size() % 2 == 0);
  for (int i = 0; i < children.size(); i += 2) {
    cast<type*>(children[i].get())->emit(os);
    os << " ";
    cast<ident*>(children[i + 1].get())->emit(os);
    if (i != children.size() - 2) {
      os << ", ";
    }
  }
}
}  // namespace ast
