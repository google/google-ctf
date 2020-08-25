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

#include "expr.h"
#include "type.h"
using namespace tao::pegtl;
namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace ast {
struct member_expr : expr {
  void emit(ostream& os) override {
    assert(children.size() == 3);
    os << "(";
    emit_left(os);
    os << "->getattribute(\"" << member_name() << "\"))";
  }
  void emit_left(ostream& os) {
    os << "(";
    cast<expr*>(children[0].get())->emit(os);
    os << ")";
  }
  std::string member_name() {
    return cast<ast::node*>(children[2].get())->data();
  }
};
struct index_expr : expr {
  void emit(ostream& os) override {
    assert(children.size() == 2);
    emit_left(os);
    os << "->getitem(";
    cast<expr*>(children[1].get())->emit(os);
    os << ")";
  }
  void emit_left(ostream& os) {
    os << "(";
    cast<expr*>(children[0].get())->emit(os);
    os << ")";
  }
  expr* key() { return cast<expr*>(children[1].get()); }
};
struct call_expr : expr {
  void emit(ostream& os) override {
    assert(children.size() == 2);
    os << "(*";
    cast<expr*>(children[0].get())->emit(os);
    os << ")({";
    bool first = true;
    // Annoyingly, if a func has no parameters, its arg list still has one arg,
    // but that arg has no children.
    if (children[1]->children.size() == 1 &&
        (children[1]->children[0]->children.empty())) {
      // no parameters.
    } else {
      for (const auto& arg : children[1]->children) {
        if (!first) {
          os << ", ";
        } else {
          first = false;
        }

        assert(arg->children.size() == 1);
        cast<expr*>(arg->children[0].get())->emit(os);
      }
    }
    os << "})";
  }
};
struct suffix : node {
  virtual void emit(ostream& os, expr* prefix) = 0;
  virtual void emit_left(ostream& os, expr* prefix, expr* param) {
    assert(0 && "Not permitted on left-hand side of assignment.");
  }
};
struct index_suffix : suffix {
  void emit(ostream& os, expr* prefix) override {
    assert(children.size() == 1);
    os << "(";
    prefix->emit(os);
    os << ").getitem(";
    cast<expr*>(children[0].get())->emit(os);
    os << ")";
  }
  void emit_left(ostream& os, expr* prefix, expr* param) override {
    assert(children.size() == 1);
    os << "(";
    prefix->emit(os);
    os << ").setitem(";
    cast<expr*>(children[0].get())->emit(os);
    os << ", (";
    param->emit(os);
    os << "))";
  }
};
struct call_suffix : suffix {
  virtual void emit_left(ostream& os, expr* prefix, expr* param) {
    std::stringstream buf;
    prefix->emit(buf);
    assert((buf.str() == "sbt_deref" || buf.str() == "(sbt_deref)") &&
           "functions other than deref() not permitted on left-hand size of "
           "assignment.");
    os << buf.str() << "(";

    assert(children.size() == 1);
    assert((children[0]->children.size() == 1) &&
           "deref must take exactly one argument.");
    cast<expr*>(children[0]->children[0].get())->emit(os);

    os << ") = (";
    param->emit(os);
    os << ");";
  }

  void emit(ostream& os, expr* prefix) override {
    assert(children.size() >= 1);

    os << "(";
    prefix->emit(os);

    // handle template type arguments
    if (children.size() > 1) {
      os << "<";
      for (int i = 0; i < children.size() - 1; ++i) {
        cast<type*>(children[i].get())->emit(os);
        if (i != children.size() - 2) os << ", ";
      }
      os << ">";
    }

    os << "(";
    auto* arg_list = cast<node*>(children.back().get());
    for (int i = 0; i < arg_list->children.size(); ++i) {
      cast<expr*>(arg_list->children[i].get())->emit(os);
      if (i != arg_list->children.size() - 1) os << ", ";
    }
    os << ")";
    os << ")";
  }
};

struct suffixed_expr : left_expr {
  void emit(ostream& os) override {
    cast<suffix*>(children[1].get())->emit(os, cast<expr*>(children[0].get()));
  }
  void emit_left(ostream& os, expr* param) override {
    cast<suffix*>(children[1].get())
        ->emit_left(os, cast<expr*>(children[0].get()), param);
  }
};
}  // namespace ast

namespace parser {
template <typename Rule, typename AstNode>
struct suffix_rearrange_impl : action_impl<AstNode> {
  static void rearrange(std::unique_ptr<parse_tree::node>& n) {
    auto& c = n->children;
    if (c.size() == 1) {
      n = move(c[0]);
      return;
    }

    auto new_node = std::unique_ptr<parse_tree::node>(new AstNode());
    new_node->id = &typeid(Rule);

    auto first = std::move(c[0]);
    auto second = std::move(c[1]);

    std::rotate(c.begin(), c.begin() + 1, c.end());
    c.resize(c.size() - 1);

    new_node->children.emplace_back(std::move(first));
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
struct action<suffixed_expr>
    : suffix_rearrange_impl<suffixed_expr, ast::suffixed_expr> {};

template <>
struct action<index_suffix> : action_impl<ast::index_suffix> {};
template <>
struct action<call_suffix> : action_impl<ast::call_suffix> {};
}  // namespace parser