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
#ifndef AST_H
#define AST_H
#include <fstream>
#include <iostream>
#include <string>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>

#include "actions.h"
#include "cast.h"
#include "grammar.h"
using namespace tao::pegtl;
namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;
using std::ostream;
namespace ast {
using result = std::string;

struct node : parse_tree::node {
  virtual void print(const std::string& padding = "") const;
  virtual std::string data() const;

  void add_source_buf(std::shared_ptr<std::string> source_buf);

  std::shared_ptr<std::string> source_buf;
};

struct root : node {};
struct program : node {
  virtual void emit(ostream& os);
};

struct ident : node {
  virtual void emit(ostream& os) {
    assert(children.size() == 0);
    // All identifiers are prefixed with "sbt_". Since there are no C or C++
    // standard library entities with that prefix, this prevents the emitted
    // code from being able to call any normal library function. Only functions
    // in the runtime which also have the "sbt_" prefix can be called.
    os << "sbt_" << data();
  }
};
}  // namespace ast

namespace parser {

template <typename Rule>
struct action : action_impl<ast::node> {};
template <>
struct action<root> : action_impl<ast::root> {};
template <>
struct action<program> : action_impl<ast::program> {};
template <>
struct action<ident> : action_impl<ast::ident> {};
}  // namespace parser
#endif
