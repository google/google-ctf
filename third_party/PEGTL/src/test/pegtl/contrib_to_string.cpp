// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/to_string.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         TAOCPP_PEGTL_TEST_ASSERT( to_string< string<> >().empty() );
         TAOCPP_PEGTL_TEST_ASSERT( ( to_string< string< 'a', 'b', 'c' > >() == "abc" ) );

         TAOCPP_PEGTL_TEST_ASSERT( to_string< istring<> >().empty() );
         TAOCPP_PEGTL_TEST_ASSERT( ( to_string< istring< 'a', 'b', 'c' > >() == "abc" ) );

         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_STRING( "" ) >().empty() );
         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_STRING( "abc" ) >() == "abc" );
         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_STRING( "AbC" ) >() == "AbC" );
         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_STRING( "abc" ) >() != "AbC" );
         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_ISTRING( "abc" ) >() == "abc" );
         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_ISTRING( "AbC" ) >() == "AbC" );
         TAOCPP_PEGTL_TEST_ASSERT( to_string< TAOCPP_PEGTL_ISTRING( "abc" ) >() != "AbC" );

         // to_string does *not* care about the outer class template
         TAOCPP_PEGTL_TEST_ASSERT( ( to_string< one< 'a', 'b', 'c' > >() == "abc" ) );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
