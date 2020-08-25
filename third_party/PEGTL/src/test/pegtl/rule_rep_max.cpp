// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< rep_max< 1, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_max< 2, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_max< 1, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_max< 2, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_max< 1, any, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_max< 2, any, any > >( __LINE__, __FILE__, false, false );

         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "b", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "bb", result_type::SUCCESS, 2 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "bbb", result_type::SUCCESS, 3 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "aaa", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "aaaa", result_type::LOCAL_FAILURE, 4 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "aaab", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 3, one< 'a' > > >( __LINE__, __FILE__, "baaab", result_type::SUCCESS, 5 );

         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 2 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ba", result_type::SUCCESS, 2 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ab", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "aba", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "abb", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "aab", result_type::SUCCESS, 3 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "abab", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ababb", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ababa", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ababab", result_type::LOCAL_FAILURE, 6 );

         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "aaa", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaa", result_type::SUCCESS, 0 );
         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaaa", result_type::SUCCESS, 1 );
         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaaaa", result_type::LOCAL_FAILURE, 6 );
         verify_rule< rep_max< 2, two< 'a' > > >( __LINE__, __FILE__, "aaaaaaa", result_type::LOCAL_FAILURE, 7 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
