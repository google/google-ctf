// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/internal/demangle_sanitise.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void test_chars( std::string a, const std::string& b )
      {
         internal::demangle_sanitise_chars( a );
         TAOCPP_PEGTL_TEST_ASSERT( a == b );
      }

      void unit_test()
      {
         const std::string s = "something that can't be demangled";
         const std::string a = internal::demangle( s.c_str() );
         TAOCPP_PEGTL_TEST_ASSERT( a == s );
         const std::string b = internal::demangle< std::string >();
         (void)b;  // Not standardised.

         test_chars( "zzz(char)1xxx", "zzz1xxx" );
         test_chars( "zzz(char)32xxx", "zzz' 'xxx" );
         test_chars( "zzz(char)48xxx", "zzz'0'xxx" );
         test_chars( "zzz(char)39xxx", "zzz'\\''xxx" );
         test_chars( "zzz(char)92xxx", "zzz'\\\\'xxx" );
         test_chars( "frobnicate<> (char)1 (char)32 (char)48 ***", "frobnicate<> 1 ' ' '0' ***" );
         test_chars( "tao::pegtl::internal::until<tao::pegtl::at<tao::pegtl::ascii::one<(char)34> >", "tao::pegtl::internal::until<tao::pegtl::at<tao::pegtl::ascii::one<'\"'> >" );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
