// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< bytes< 0 > >( __LINE__, __FILE__, false, false );

         verify_rule< bytes< 0 > >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< bytes< 0 > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 1 );

         verify_analyze< bytes< 1 > >( __LINE__, __FILE__, true, false );

         for( char c = 0; c < 127; ++c ) {
            verify_char< bytes< 1 > >( __LINE__, __FILE__, c, result_type::SUCCESS );
         }
         verify_rule< bytes< 1 > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< bytes< 1 > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 1 );

         verify_analyze< bytes< 2 > >( __LINE__, __FILE__, true, false );
         verify_analyze< bytes< 42 > >( __LINE__, __FILE__, true, false );

         verify_rule< bytes< 3 > >( __LINE__, __FILE__, "abcd", result_type::SUCCESS, 1 );
         verify_rule< bytes< 4 > >( __LINE__, __FILE__, "abcd", result_type::SUCCESS, 0 );
         verify_rule< bytes< 5 > >( __LINE__, __FILE__, "abcd", result_type::LOCAL_FAILURE, 4 );

         verify_rule< bytes< 4 > >( __LINE__, __FILE__, "abcdefghij", result_type::SUCCESS, 6 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
