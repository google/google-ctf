// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< two< 'a' > >( __LINE__, __FILE__, true, false );

         verify_rule< two< 'a' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< two< 'a' > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_rule< two< 'a' > >( __LINE__, __FILE__, "ab", result_type::LOCAL_FAILURE, 2 );
         verify_rule< two< 'a' > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 0 );
         verify_rule< two< 'a' > >( __LINE__, __FILE__, "aaa", result_type::SUCCESS, 1 );
         verify_rule< two< 'a' > >( __LINE__, __FILE__, "aaaa", result_type::SUCCESS, 2 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
