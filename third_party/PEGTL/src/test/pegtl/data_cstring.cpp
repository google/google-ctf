// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/internal/cstring_reader.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule,
                template< typename... > class Action = nothing,
                template< typename... > class Control = normal,
                typename... States >
      bool parse_cstring( const char* string, const char* source, const std::size_t maximum, States&&... st )
      {
         buffer_input< internal::cstring_reader > in( source, maximum, string );
         return parse< Rule, Action, Control >( in, st... );
      }

      struct test_grammar : seq< string< 'a', 'b' >, discard, string< 'c', 'd' >, discard, any, any, discard, eof >
      {
      };

      void unit_test()
      {
         const char* test_data = "abcdef";
         TAOCPP_PEGTL_TEST_ASSERT( parse_cstring< test_grammar >( test_data, "test data", 2 ) );
         TAOCPP_PEGTL_TEST_ASSERT( !parse_cstring< test_grammar >( test_data, "test data", 1 ) );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
