// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <cstring>

#include "test.hpp"

#include <tao/pegtl.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         char data[ 12 ];
         std::memcpy( data, "foo\0bar\0baz", 12 );
         char* argv[] = { data, data + 4, data + 8 };
         argv_input<> in( argv, 1 );
         TAOCPP_PEGTL_TEST_ASSERT( in.source() == "argv[1]" );
         const auto result = parse< string< 'b', 'a', 'r' > >( in );
         TAOCPP_PEGTL_TEST_ASSERT( result );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
