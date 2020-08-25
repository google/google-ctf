// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/json.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule >
      void verify_file_fail( const std::size_t line, const char* file, const std::string& s )
      {
         file_input<> in( s );
         try {
            parse< Rule >( in );
            TAOCPP_PEGTL_TEST_FAILED( "expected exception" );
         }
         catch( ... ) {
         }
      }

      using GRAMMAR = must< json::text, eof >;

      void unit_test()
      {
         verify_analyze< GRAMMAR >( __LINE__, __FILE__, true, false );

         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "{}", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, " [ ] ", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, " { } ", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "   [   ]   ", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "   {   }   ", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[[{}],[],{}]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[ null, true, false, 0, 1, 2, 123, 1.23, 0.12, -1, -0, -1.23, \"\", \"abc\" ]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\b\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\f\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\n\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\r\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\t\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\/\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\\\\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\\"\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\u002C\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\u002c\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"ab\\u002Ccd\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"ab\\u002ccd\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\uD834\\uDD1E\"]", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\uD834\"]", result_type::SUCCESS, 0 );           // unfortunately, this is valid for the grammar...
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\\uDD1E\"]", result_type::SUCCESS, 0 );           // ...although both inputs are invalid in unicode.
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\xC3\x84\"]", result_type::SUCCESS, 0 );          // German a-umlaut
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\xF4\x8F\xBF\xBF\"]", result_type::SUCCESS, 0 );  // largest allowed codepoint U+10FFFF
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "[\"\U0010FFFF\"]", result_type::SUCCESS, 0 );        // largest allowed codepoint U+10FFFF

         verify_fail< GRAMMAR >( __LINE__, __FILE__, "" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, " " );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "   " );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, " [" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, " ]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[ " );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "] " );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, " [ " );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, " ] " );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\a\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\c\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\d\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\e\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\v\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\'\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\b\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\f\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\n\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\r\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\t\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\\\\\\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\\u12\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\xFF\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\xF4\x90\x80\x80\"]" );
         verify_fail< GRAMMAR >( __LINE__, __FILE__, "[\"\xF7\xBF\xBF\xBF\"]" );

         TAOCPP_PEGTL_TEST_ASSERT( parse< GRAMMAR >( file_input<>( "src/test/pegtl/data/pass1.json" ) ) );
         TAOCPP_PEGTL_TEST_ASSERT( parse< GRAMMAR >( file_input<>( "src/test/pegtl/data/pass2.json" ) ) );
         TAOCPP_PEGTL_TEST_ASSERT( parse< GRAMMAR >( file_input<>( "src/test/pegtl/data/pass3.json" ) ) );

         TAOCPP_PEGTL_TEST_ASSERT( parse< GRAMMAR >( file_input<>( "src/test/pegtl/data/blns.json" ) ) );

         // verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail1.json" ); // disabled as it is valid now
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail2.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail3.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail4.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail5.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail6.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail7.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail8.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail9.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail10.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail11.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail12.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail13.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail14.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail15.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail16.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail17.json" );
         // verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail18.json" ); // disabled as deep nesting is allowed
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail19.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail20.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail21.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail22.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail23.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail24.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail25.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail26.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail27.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail28.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail29.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail30.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail31.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail32.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail33.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail34.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail35.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail36.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail37.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail38.json" );
         verify_file_fail< GRAMMAR >( __LINE__, __FILE__, "src/test/pegtl/data/fail39.json" );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
