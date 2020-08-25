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
#pragma once
#include <fstream>
#include <iostream>
#include <string>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
using namespace tao::pegtl;
namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace parser {
template <typename AstNode>
void extend_node(std::unique_ptr<parse_tree::node>& node) {
  std::unique_ptr<parse_tree::node> ret(new AstNode());
  ret->begin = node->begin;
  ret->end = node->end;
  ret->children = std::move(node->children);
  ret->id = node->id;
  node = move(ret);
}

template <typename AstNode>
struct action_impl {
  template <typename Input>
  static void apply(const Input&, parse_tree::state& s) {
    extend_node<AstNode>(s.back());
  }
};
}  // namespace parser
