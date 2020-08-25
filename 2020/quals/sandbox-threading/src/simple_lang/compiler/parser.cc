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
#include <fstream>
#include <iostream>
#include <string>
#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>

#include "ast.h"
#include "binop.h"
#include "expr.h"
#include "grammar.h"
#include "stmt.h"
#include "suffixed_expr.h"
#include "type.h"

using namespace tao::pegtl;

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

std::string readall(std::istream& is) {
  char temp[1024];
  std::string ret;
  while (!is.eof()) {
    is.read(temp, 1024);
    ret.append(temp, is.gcount());
  }
  return ret;
}

// Compile some program text.
std::unique_ptr<ast::program> compile(
    std::shared_ptr<std::string> text,
    const std::string& file_comment = "<source>") {
  pegtl::memory_input<> in(text->data(), text->size(), file_comment);
  pegtl::analyze<parser::program>();

  parse_tree::state s;
  pegtl::parse<parser::root, parser::action,
               parse_tree::make_builder<parser::store_simple,
                                        parser::store_content>::type>(in, s);

  auto program = std::unique_ptr<ast::program>(
      cast<ast::program*>(s.root().children[0]->children[0].release()));
  program->add_source_buf(text);
  return program;
}

int _memfd_create(const char *name, unsigned int flags) { return syscall(319, name, flags); }

int main(int argc, char** argv) {
  assert(argc >= 3);
  std::string* program = new std::string();

  {
    std::ifstream is(argv[1]);
    assert(is.is_open());
    *program = readall(is);
  }

  std::ofstream os(argv[2]);
  assert(os.is_open());

  try {
    std::unique_ptr<ast::program> x =
        compile(std::shared_ptr<std::string>(program), argv[1]);
    //x->print();
    x->emit(os);

  } catch (std::exception& ex) {
    std::cerr << "error: " << ex.what() << std::endl;
    return -1;
  }

  return 0;
}
