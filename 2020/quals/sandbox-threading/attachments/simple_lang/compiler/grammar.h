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
#ifndef GRAMMAR_H
#define GRAMMAR_H

#include <fstream>
#include <iostream>
#include <string>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>

using namespace tao::pegtl;

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace parser {
template <typename>
struct store_simple : std::false_type {};
template <typename>
struct store_content : std::false_type {};

namespace str_literal {
// clang-format off
		struct escaped_x : seq< one< 'x' >, rep< 2, must< xdigit > > > {};
		struct escaped_u : seq< one< 'u' >, rep< 4, must< xdigit > > > {};
		struct escaped_U : seq< one< 'U' >, rep< 8, must< xdigit > > > {};
		struct escaped_c : one< '\'', '"', '?', '\\', 'a', 'b', 'f', 'n', 'r', 't', 'v' > {};

		struct escaped : sor< escaped_x,
			escaped_u,
			escaped_U,
			escaped_c > {};

		struct character : if_must_else< one< '\\' >, escaped, ascii::any > {};
		struct unpad_literal : if_must< one< '"' >, until< one< '"' >, character > > {};

		struct literal : pad<unpad_literal, space> {};
	};
	template<> struct store_content<str_literal::literal> : std::true_type {};

	struct null_node : seq<> {};

	struct lparen : pad< one< '(' >, space > {};
	struct rparen : pad< one< ')' >, space > {};
	struct lbrack : pad< one< '[' >, space > {};
	struct rbrack : pad< one< ']' >, space > {};
	struct lbrace : pad< one< '{' >, space > {};
	struct rbrace : pad< one< '}' >, space > {};
	struct plus : pad< one< '+' >, space > {};
	template<> struct store_simple<plus> : std::true_type {};
	struct minus : pad< one< '-' >, space > {};
	template<> struct store_simple<minus> : std::true_type {};
	struct multiply : pad< one< '*' >, space > {};
	template<> struct store_simple<multiply> : std::true_type {};
	struct divide : pad< one< '/' >, space > {};
	template<> struct store_simple<divide> : std::true_type {};
	struct langle : pad< one< '<' >, space > {};
	template<> struct store_simple<langle> : std::true_type {};
	struct rangle : pad< one< '>' >, space > {};
	template<> struct store_simple<rangle> : std::true_type {};
	struct le : pad< pegtl::string<'<', '='>, space > {};
	template<> struct store_simple<le> : std::true_type {};
	struct ge : pad< pegtl::string<'>', '='>, space > {};
	template<> struct store_simple<ge> : std::true_type {};
	struct eq : pad< pegtl::string<'=', '='>, space > {};
	template<> struct store_simple<eq> : std::true_type {};
	struct ne : pad< pegtl::string<'!', '='>, space > {};
	template<> struct store_simple<ne> : std::true_type {};
	struct and_k : pad< pegtl::string<'&', '&'>, space > {};
	template<> struct store_simple<and_k> : std::true_type {};
	struct or_k : pad< pegtl::string<'|', '|'>, space > {};
	template<> struct store_simple< or_k > : std::true_type {};
	struct comma : pad< one< ',' >, space > {};

	struct langle_scope : pad< one< '<' >, space > {};
	struct rangle_scope : pad< one< '>' >, space > {};

	struct def : pad<pegtl::string<'d', 'e', 'f'>, space> {};
	struct return_k : pad<pegtl::string<'r', 'e', 't', 'u', 'r', 'n'>, space> {};

	struct void_k : pad<pegtl::string<'v', 'o', 'i', 'd'>, space> {};
	struct char_k : pad<pegtl::string<'c', 'h', 'a', 'r'>, space> {};
	struct int32_k : pad<pegtl::string<'i', 'n', 't', '3', '2'>, space> {};
	struct int64_k : pad<pegtl::string<'i', 'n', 't', '6', '4'>, space> {};
	struct uint32_k : pad<pegtl::string<'u', 'i', 'n', 't', '3', '2'>, space> {};
	struct uint64_k : pad<pegtl::string<'u', 'i', 'n', 't', '6', '4'>, space> {};
	struct string_k : pad<pegtl::string<'s', 't', 'r', 'i', 'n', 'g'>, space> {};
	struct semaphore_k : pad<pegtl::string<'s', 'e', 'm', 'a', 'p', 'h', 'o', 'r', 'e'>, space> {};
	struct thread_k : pad<pegtl::string<'t', 'h', 'r', 'e', 'a', 'd'>, space> {};
	struct atomic_type : sor< void_k, char_k, int32_k, int64_k, uint32_k, uint64_k, string_k, semaphore_k, thread_k> {};
	template<> struct store_content<atomic_type> : std::true_type {};

	struct array_k : pad<pegtl::string<'a', 'r', 'r', 'a', 'y'>, space> {};
	struct ref_k : pad<pegtl::string<'r', 'e', 'f'>, space> {};
	struct func_k : pad<pegtl::string<'f', 'u', 'n', 'c'>, space> {};

	struct var_type;
	struct integer;
	struct array_type : if_must<array_k, langle_scope, var_type, opt<if_must<comma, integer>>, rangle_scope> {};
	template<> struct store_simple<array_type> : std::true_type {};
	struct ref_type : if_must<ref_k, langle_scope, var_type, rangle_scope> {};
	template<> struct store_simple<ref_type> : std::true_type {};
	struct func_type : if_must<func_k, langle_scope, pegtl::list<var_type, comma>, rangle_scope> {};
	template<> struct store_simple<func_type> : std::true_type {};

	struct semicolon : pad< one< ';' >, space > {};

	struct var_type : sor<atomic_type, ref_type, array_type, func_type> {};

	struct expr;
	struct stmt;
	struct stmt_block;

	struct assign : pad< one< '=' >, space > {};

	struct integer : pad<pegtl::plus< digit >, space> {};
	template<> struct store_content<integer> : std::true_type {};
	struct ident : pad<seq<not_at<var_type>, identifier>, space> {};
	template<> struct store_content<ident> : std::true_type {};
	struct variable : seq<ident> {};
	template<> struct store_simple<variable> : std::true_type {};
	struct paren_expr : seq <lparen, expr, rparen> {};
	template<> struct store_simple<paren_expr> : std::true_type {};
	struct atomic_expr : sor<variable, integer, paren_expr, str_literal::literal> {};

	struct var_decl : if_must<var_type, ident, opt<if_must<assign, expr>>, semicolon> {};
	template<> struct store_simple<var_decl> : std::true_type {};

	struct typed_arg_decl_list : opt<list_tail<if_must<var_type, ident>, comma>> {};
	template<> struct store_simple<typed_arg_decl_list> : std::true_type {};

	struct arg_list : opt<list_tail<expr, comma>> {};
	template<> struct store_simple<arg_list> : std::true_type {};

	struct index_suffix : if_must<lbrack, expr, rbrack> {};
	template<> struct store_simple<index_suffix> : std::true_type {};
	struct call_suffix : seq<opt<seq<langle_scope, var_type, rangle_scope>>, if_must<lparen, arg_list, rparen>> {};
	template<> struct store_simple<call_suffix> : std::true_type {};
	struct suffixed_expr : seq<atomic_expr, star<sor<index_suffix, call_suffix>>> {};
	template<> struct store_simple<suffixed_expr> : std::true_type {};

	struct less_than : seq<langle, not_at<one<'='>>> {};
	struct greater_than : seq<rangle, not_at<one<'='>>> {};

	struct mul_expr : list<suffixed_expr, sor<multiply, divide>> {};
	template<> struct store_simple<mul_expr> : std::true_type {};
	struct add_expr : list<mul_expr, sor<plus, minus>> {};
	template<> struct store_simple<add_expr> : std::true_type {};
	struct comp_expr : list<add_expr, sor<le, less_than, ge, greater_than>> {};
	template<> struct store_simple<comp_expr> : std::true_type {};
	struct eqne_expr : list<comp_expr, sor<eq, ne>> {};
	template<> struct store_simple<eqne_expr> : std::true_type {};
	struct andor_expr : list<eqne_expr, sor<and_k, or_k>> {};
	template<> struct store_simple<andor_expr> : std::true_type {};

	struct expr : sor<andor_expr> {};

	struct while_k : pad<pegtl::string<'w', 'h', 'i', 'l', 'e'>, space> {};
	struct if_k : pad<pegtl::string<'i', 'f'>, space> {};

	struct assign_stmt : seq<suffixed_expr, assign, expr, semicolon> {};
	template<> struct store_simple<assign_stmt> : std::true_type {};
	struct if_stmt : if_must<if_k, lparen, expr, rparen, stmt> {};
	template<> struct store_simple<if_stmt> : std::true_type {};
	struct while_stmt : if_must<while_k, lparen, expr, rparen, stmt> {};
	template<> struct store_simple<while_stmt> : std::true_type {};
	struct return_stmt : if_must<return_k, expr, semicolon> {};
	template<> struct store_simple<return_stmt> : std::true_type {};

	struct typed_def_stmt : if_must<def, var_type, ident, lparen, typed_arg_decl_list, rparen, stmt> {};
	template<> struct store_simple<typed_def_stmt> : std::true_type {};
	struct expr_stmt : seq<expr, semicolon> {};
	template<> struct store_simple<expr_stmt> : std::true_type {};
	struct stmt : sor<if_must<lbrace, stmt_block, rbrace>, var_decl, assign_stmt, expr_stmt, if_stmt, while_stmt, return_stmt, semicolon> {};
	struct stmt_block : seq<star<stmt>> {};
	template<> struct store_simple<stmt_block> : std::true_type {};

	struct program : must<star<sor<typed_def_stmt, var_decl>>> {};
	template<> struct store_simple<program> : std::true_type {};
	struct root : must<program, eof> {};
	template<> struct store_simple<root> : std::true_type {};
}
#endif
