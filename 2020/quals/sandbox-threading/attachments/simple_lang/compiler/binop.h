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

#include "actions.h"
#include "expr.h"
using namespace tao::pegtl;
namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace ast {
struct binop : node {
  virtual void emit(ostream& os) = 0;
};
struct add_op : binop {
  void emit(ostream& os) override { os << " + "; }
};
struct sub_op : binop {
  void emit(ostream& os) override { os << " - "; }
};
struct mul_op : binop {
  void emit(ostream& os) override { os << " * "; }
};
struct div_op : binop {
  void emit(ostream& os) override { os << " / "; }
};
struct lt_op : binop {
  void emit(ostream& os) override { os << " < "; }
};
struct gt_op : binop {
  void emit(ostream& os) override { os << " > "; }
};
struct le_op : binop {
  void emit(ostream& os) override { os << " <= "; }
};
struct ge_op : binop {
  void emit(ostream& os) override { os << " >= "; }
};
struct eq_op : binop {
  void emit(ostream& os) override { os << " == "; }
};
struct ne_op : binop {
  void emit(ostream& os) override { os << " != "; }
};
struct and_op : binop {
  void emit(ostream& os) override { os << " && "; }
};
struct or_op : binop {
  void emit(ostream& os) override { os << " || "; }
};
struct binop_expr : expr {
  void emit(ostream& os) override {
    assert(children.size() == 3);
    binop& op = *cast<binop*>(children[1].get());
    os << "(";
    cast<expr*>(children[0].get())->emit(os);
    os << ")";
    op.emit(os);
    os << "(";
    cast<expr*>(children[2].get())->emit(os);
    os << ")";
  }
};
}  // namespace ast

namespace parser {
template <typename Rule, typename AstNode>
struct rearrange_impl : action_impl<AstNode> {
  static void rearrange(std::unique_ptr<parse_tree::node>& n) {
    auto& c = n->children;
    if (c.size() == 1) {
      n = move(c[0]);
      return;
    }
    assert(c.size() % 2 == 1);
    if (c.size() <= 3) return;

    auto new_node = std::unique_ptr<parse_tree::node>(new AstNode());
    new_node->id = &typeid(Rule);

    auto first = std::move(c[0]);
    auto op = std::move(c[1]);
    auto second = std::move(c[2]);

    std::rotate(c.begin(), c.begin() + 2, c.end());
    c.resize(c.size() - 2);

    new_node->children.emplace_back(std::move(first));
    new_node->children.emplace_back(std::move(op));
    new_node->children.emplace_back(std::move(second));

    c[0] = std::move(new_node);
    rearrange(n);
  }

  template <typename Input>
  static void apply(const Input& i, parse_tree::state& s) {
    action_impl<AstNode>::apply(i, s);
    rearrange(s.back());
  }
};
template <>
struct action<mul_expr> : rearrange_impl<mul_expr, ast::binop_expr> {};
template <>
struct action<add_expr> : rearrange_impl<add_expr, ast::binop_expr> {};
template <>
struct action<comp_expr> : rearrange_impl<comp_expr, ast::binop_expr> {};
template <>
struct action<eqne_expr> : rearrange_impl<eqne_expr, ast::binop_expr> {};
template <>
struct action<andor_expr> : rearrange_impl<andor_expr, ast::binop_expr> {};

template <>
struct action<plus> : action_impl<ast::add_op> {};
template <>
struct action<minus> : action_impl<ast::sub_op> {};
template <>
struct action<multiply> : action_impl<ast::mul_op> {};
template <>
struct action<divide> : action_impl<ast::div_op> {};
template <>
struct action<langle> : action_impl<ast::lt_op> {};
template <>
struct action<rangle> : action_impl<ast::gt_op> {};
template <>
struct action<le> : action_impl<ast::le_op> {};
template <>
struct action<ge> : action_impl<ast::ge_op> {};
template <>
struct action<eq> : action_impl<ast::eq_op> {};
template <>
struct action<ne> : action_impl<ast::ne_op> {};
template <>
struct action<and_k> : action_impl<ast::and_op> {};
template <>
struct action<or_k> : action_impl<ast::or_op> {};
}  // namespace parser
