// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< plus< eof > >( __LINE__, __FILE__, false, true );
         verify_analyze< plus< any > >( __LINE__, __FILE__, true, false );
         verify_analyze< plus< eof, eof, eof > >( __LINE__, __FILE__, false, true );
         verify_analyze< plus< any, eof, any > >( __LINE__, __FILE__, true, false );

         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 0 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "aaa", result_type::SUCCESS, 0 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "b", result_type::LOCAL_FAILURE, 1 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "ab", result_type::SUCCESS, 1 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "aab", result_type::SUCCESS, 1 );
         verify_rule< plus< one< 'a' > > >( __LINE__, __FILE__, "aaab", result_type::SUCCESS, 1 );

         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "b", result_type::LOCAL_FAILURE, 1 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ab", result_type::SUCCESS, 0 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ac", result_type::LOCAL_FAILURE, 2 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "aa", result_type::LOCAL_FAILURE, 2 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "aba", result_type::SUCCESS, 1 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "abb", result_type::SUCCESS, 1 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "abc", result_type::SUCCESS, 1 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "abab", result_type::SUCCESS, 0 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ababa", result_type::SUCCESS, 1 );
         verify_rule< plus< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ababb", result_type::SUCCESS, 1 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
