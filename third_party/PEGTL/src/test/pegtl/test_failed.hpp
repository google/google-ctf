// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_TAOCPP_PEGTL_TEST_FAILED_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_TAOCPP_PEGTL_TEST_FAILED_HPP

#include <iostream>

#include <tao/pegtl/internal/demangle.hpp>

#define TAOCPP_PEGTL_TEST_FAILED( MeSSaGe )         \
   do {                                             \
      std::cerr << "pegtl: unit test failed for [ " \
                << internal::demangle< Rule >()     \
                << " ] "                            \
                << MeSSaGe                          \
                << " in line [ "                    \
                << line                             \
                << " ] file [ "                     \
                << file << " ]"                     \
                << std::endl;                       \
      ++failed;                                     \
   } while( false )

#endif
