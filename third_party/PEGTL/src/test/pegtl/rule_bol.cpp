// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< bol >( __LINE__, __FILE__, false, false );

         verify_only< bol >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );

         for( char i = 1; i < 127; ++i ) {
            const char s[] = { i, 0 };
            verify_only< bol >( __LINE__, __FILE__, s, result_type::SUCCESS, 1 );
         }
         verify_only< seq< alpha, bol > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_only< seq< alpha, bol > >( __LINE__, __FILE__, "ab", result_type::LOCAL_FAILURE, 2 );
         verify_only< seq< alpha, bol, alpha > >( __LINE__, __FILE__, "ab", result_type::LOCAL_FAILURE, 2 );
         verify_only< seq< alpha, eol, bol, alpha, eof > >( __LINE__, __FILE__, "a\nb", result_type::SUCCESS, 0 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
