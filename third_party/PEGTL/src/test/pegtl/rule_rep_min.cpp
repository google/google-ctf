// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< rep_min< 0, eof > >( __LINE__, __FILE__, false, true );
         verify_analyze< rep_min< 1, eof > >( __LINE__, __FILE__, false, true );
         verify_analyze< rep_min< 0, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_min< 1, any > >( __LINE__, __FILE__, true, false );

         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "aa", result_type::LOCAL_FAILURE, 2 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "b", result_type::LOCAL_FAILURE, 1 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "bb", result_type::LOCAL_FAILURE, 2 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "bbb", result_type::LOCAL_FAILURE, 3 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "aaa", result_type::SUCCESS, 0 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "aaaa", result_type::SUCCESS, 0 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "aaab", result_type::SUCCESS, 1 );
         verify_rule< rep_min< 3, one< 'a' > > >( __LINE__, __FILE__, "baaab", result_type::LOCAL_FAILURE, 5 );

         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "aa", result_type::LOCAL_FAILURE, 2 );
         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "aaa", result_type::LOCAL_FAILURE, 3 );
         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaa", result_type::SUCCESS, 0 );
         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaaa", result_type::SUCCESS, 1 );
         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaaaa", result_type::SUCCESS, 0 );
         verify_rule< rep_min< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaaaaa", result_type::SUCCESS, 1 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
