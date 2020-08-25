// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< istring<> >( __LINE__, __FILE__, false, false );
         verify_analyze< istring< 1 > >( __LINE__, __FILE__, true, false );
         verify_analyze< istring< 1, 2 > >( __LINE__, __FILE__, true, false );
         verify_analyze< istring< 1, 2, 3, 4 > >( __LINE__, __FILE__, true, false );
         verify_analyze< istring< 1, 2, 3, 4, 5, 6, 7 > >( __LINE__, __FILE__, true, false );

         verify_rule< istring<> >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "b", result_type::LOCAL_FAILURE, 1 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "c", result_type::LOCAL_FAILURE, 1 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "aa", result_type::LOCAL_FAILURE, 2 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "aB", result_type::SUCCESS, 0 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "AB", result_type::SUCCESS, 0 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "Ab", result_type::SUCCESS, 0 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "ac", result_type::LOCAL_FAILURE, 2 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "ba", result_type::LOCAL_FAILURE, 2 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "bb", result_type::LOCAL_FAILURE, 2 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "aab", result_type::LOCAL_FAILURE, 3 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "aab", result_type::LOCAL_FAILURE, 3 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "ab", result_type::SUCCESS, 0 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "aba", result_type::SUCCESS, 1 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "Abb", result_type::SUCCESS, 1 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "abc", result_type::SUCCESS, 1 );
         verify_rule< istring< 'a', 'b' > >( __LINE__, __FILE__, "aBab", result_type::SUCCESS, 2 );
         verify_rule< istring< 'a', '0' > >( __LINE__, __FILE__, "a0A0", result_type::SUCCESS, 2 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
