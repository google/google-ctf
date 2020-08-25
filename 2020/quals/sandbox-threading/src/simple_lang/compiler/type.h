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
#ifndef TYPE_H
#define TYPE_H

#include <fstream>
#include <iostream>
#include <string>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>

#include "ast.h"
#include "expr.h"

using namespace tao::pegtl;
namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace ast {
struct type : node {
  virtual void emit(ostream& os){};
};
struct atomic_type : type {
  void emit(ostream& os) override {
    std::string t = data();
    if (t == "void")
      os << "void";
    else if (t == "char")
      os << "achar";
    else if (t == "int32")
      os << "int32";
    else if (t == "uint32")
      os << "uint32";
    else if (t == "int64")
      os << "int64";
    else if (t == "uint64")
      os << "uint64";
    else if (t == "string")
      os << "dynamic_array<achar>";
    else if (t == "semaphore")
      os << "semaphore";
    else if (t == "thread")
      os << "thread";
    else {
      std::cerr << "Unexpected type: " << t;
      assert(false);
    }
  };
};
struct ref_type : type {
  virtual void emit(ostream& os) {
    os << "ref<";
    cast<type*>(children[0].get())->emit(os);
    os << ">";
  };
};
struct array_type : type {
  virtual void emit(ostream& os) {
    if (children.size() == 2) {
      os << "fixed_array<";
      cast<type*>(children[0].get())->emit(os);
      os << ", ";
      cast<integer*>(children[1].get())->emit(os);
      os << ">";
    } else if (children.size() == 1) {
      os << "dynamic_array<";
      cast<type*>(children[0].get())->emit(os);
      os << ">";
    } else {
      assert(false);
    }
  };
};
struct func_type : type {
  virtual void emit(ostream& os) {
    assert(children.size() >= 1);
    os << "func<";
    for (int i = 0; i < children.size(); ++i) {
      cast<type*>(children[i].get())->emit(os);
      if (i != children.size() - 1) os << ",";
    }
    os << ">";
  };
};
}  // namespace ast

namespace parser {
template <>
struct action<atomic_type> : action_impl<ast::atomic_type> {};
template <>
struct action<ref_type> : action_impl<ast::ref_type> {};
template <>
struct action<array_type> : action_impl<ast::array_type> {};
template <>
struct action<func_type> : action_impl<ast::func_type> {};
}  // namespace parser

#endif
