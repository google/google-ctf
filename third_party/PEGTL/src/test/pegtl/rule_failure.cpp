// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< failure >( __LINE__, __FILE__, true, false );  // "Success implies consumption" is true because "success" never happens.

         verify_rule< failure >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );

         for( char i = 1; i < 127; ++i ) {
            verify_char< failure >( __LINE__, __FILE__, i, result_type::LOCAL_FAILURE );
         }
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
