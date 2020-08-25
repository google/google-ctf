// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_TEST_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_TEST_HPP

#include <cassert>
#include <cstddef>
#include <iostream>

#include <tao/pegtl.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      std::size_t failed = 0;
      std::vector< std::pair< std::string, std::string > > applied;

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "test_action.hpp"
#include "test_assert.hpp"
#include "test_failed.hpp"
#include "test_rule.hpp"

#include "verify_char.hpp"
#include "verify_fail.hpp"
#include "verify_rule.hpp"

#include "verify_analyze.hpp"

#endif
