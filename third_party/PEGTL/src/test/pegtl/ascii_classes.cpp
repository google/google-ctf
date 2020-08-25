// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< alnum >( __LINE__, __FILE__, true, false );
         verify_analyze< alpha >( __LINE__, __FILE__, true, false );
         verify_analyze< any >( __LINE__, __FILE__, true, false );
         verify_analyze< blank >( __LINE__, __FILE__, true, false );
         verify_analyze< digit >( __LINE__, __FILE__, true, false );
         verify_analyze< eol >( __LINE__, __FILE__, true, false );
         verify_analyze< identifier_first >( __LINE__, __FILE__, true, false );
         verify_analyze< identifier_other >( __LINE__, __FILE__, true, false );
         verify_analyze< lower >( __LINE__, __FILE__, true, false );
         verify_analyze< nul >( __LINE__, __FILE__, true, false );
         verify_analyze< print >( __LINE__, __FILE__, true, false );
         verify_analyze< seven >( __LINE__, __FILE__, true, false );
         verify_analyze< space >( __LINE__, __FILE__, true, false );
         verify_analyze< upper >( __LINE__, __FILE__, true, false );
         verify_analyze< xdigit >( __LINE__, __FILE__, true, false );

         verify_analyze< not_one< 'a' > >( __LINE__, __FILE__, true, false );
         verify_analyze< not_one< 'a', 'z' > >( __LINE__, __FILE__, true, false );
         verify_analyze< not_range< 'a', 'z' > >( __LINE__, __FILE__, true, false );
         verify_analyze< one< 'a' > >( __LINE__, __FILE__, true, false );
         verify_analyze< one< 'a', 'z' > >( __LINE__, __FILE__, true, false );
         verify_analyze< range< 'a', 'z' > >( __LINE__, __FILE__, true, false );
         verify_analyze< ranges< 'a', 'z' > >( __LINE__, __FILE__, true, false );
         verify_analyze< ranges< 'a', 'z', '4' > >( __LINE__, __FILE__, true, false );

         verify_rule< alnum >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< alpha >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< any >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< blank >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< digit >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< eol >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< identifier_first >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< identifier_other >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< lower >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< nul >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< print >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< seven >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< space >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< upper >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< xdigit >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );

         verify_rule< not_one< 'a' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< not_one< 'a', 'z' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< not_range< 'a', 'z' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< one< 'a' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< one< 'a', 'z' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< range< 'a', 'z' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< ranges< 'a', 'z' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< ranges< 'a', 'z', '4' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );

         for( int i = -100; i < 200; ++i ) {
            const auto c = char( i );

            const bool is_blank = ( c == ' ' ) || ( c == '\t' );
            const bool is_digit = ( '0' <= c ) && ( c <= '9' );
            const bool is_lower = ( 'a' <= c ) && ( c <= 'z' );
            const bool is_print = ( ( ' ' <= c ) && ( c <= 126 ) );
            const bool is_seven = ( ( i >= 0 ) && ( i <= 127 ) );
            const bool is_space = ( c == '\n' ) || ( c == '\r' ) || ( c == '\v' ) || ( c == '\f' );
            const bool is_upper = ( 'A' <= c ) && ( c <= 'Z' );
            const bool is_xalpha = ( ( 'a' <= c ) && ( c <= 'f' ) ) || ( ( 'A' <= c ) && ( c <= 'F' ) );

            const bool is_newline = ( c == '\n' );

            const bool is_ident_first = ( c == '_' ) || is_lower || is_upper;
            const bool is_ident_other = is_ident_first || is_digit;

            verify_char< alnum >( __LINE__, __FILE__, c, is_lower || is_upper || is_digit );
            verify_char< alpha >( __LINE__, __FILE__, c, is_lower || is_upper );
            verify_char< any >( __LINE__, __FILE__, c, true );
            verify_char< blank >( __LINE__, __FILE__, c, is_blank );
            verify_char< digit >( __LINE__, __FILE__, c, is_digit );
            verify_char< eol >( __LINE__, __FILE__, c, is_newline );
            verify_char< identifier_first >( __LINE__, __FILE__, c, is_ident_first );
            verify_char< identifier_other >( __LINE__, __FILE__, c, is_ident_other );
            verify_char< lower >( __LINE__, __FILE__, c, is_lower );
            verify_char< nul >( __LINE__, __FILE__, c, c == 0 );
            verify_char< print >( __LINE__, __FILE__, c, is_print );
            verify_char< seven >( __LINE__, __FILE__, c, is_seven );
            verify_char< space >( __LINE__, __FILE__, c, is_blank || is_space );
            verify_char< upper >( __LINE__, __FILE__, c, is_upper );
            verify_char< xdigit >( __LINE__, __FILE__, c, is_digit || is_xalpha );

            const bool is_one = ( c == '#' ) || ( c == 'a' ) || ( c == ' ' );
            const bool is_range = ( 20 <= c ) && ( c <= 120 );
            const bool is_ranges = is_range || ( c == 3 );

            verify_char< not_one< 'P' > >( __LINE__, __FILE__, c, c != 'P' );
            verify_char< not_one< 'a', '#', ' ' > >( __LINE__, __FILE__, c, !is_one );
            verify_char< not_range< 20, 120 > >( __LINE__, __FILE__, c, !is_range );
            verify_char< one< 'T' > >( __LINE__, __FILE__, c, c == 'T' );
            verify_char< one< 'a', '#', ' ' > >( __LINE__, __FILE__, c, is_one );
            verify_char< range< 20, 120 > >( __LINE__, __FILE__, c, is_range );
            verify_char< ranges< 20, 120 > >( __LINE__, __FILE__, c, is_range );
            verify_char< ranges< 20, 120, 3 > >( __LINE__, __FILE__, c, is_ranges );

            verify_char< eolf >( __LINE__, __FILE__, c, is_newline );
         }
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
