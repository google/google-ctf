// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_MAIN_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_MAIN_HPP

#include <cstdlib>

int main( int, char** argv )
{
   tao::TAOCPP_PEGTL_NAMESPACE::unit_test();

   if( tao::TAOCPP_PEGTL_NAMESPACE::failed ) {
      std::cerr << "pegtl: unit test " << argv[ 0 ] << " failed " << tao::TAOCPP_PEGTL_NAMESPACE::failed << std::endl;
   }
   return ( tao::TAOCPP_PEGTL_NAMESPACE::failed == 0 ) ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif
