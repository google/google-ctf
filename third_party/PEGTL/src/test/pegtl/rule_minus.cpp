// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< minus< alpha, digit > >( __LINE__, __FILE__, true, false );
         verify_analyze< minus< opt< alpha >, digit > >( __LINE__, __FILE__, false, false );

         verify_rule< minus< alnum, digit > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< minus< alnum, digit > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< minus< alnum, digit > >( __LINE__, __FILE__, "1", result_type::LOCAL_FAILURE, 1 );
         verify_rule< minus< alnum, digit > >( __LINE__, __FILE__, "%", result_type::LOCAL_FAILURE, 1 );
         verify_rule< minus< alnum, digit > >( __LINE__, __FILE__, "a%", result_type::SUCCESS, 1 );

         verify_rule< must< minus< alnum, digit > > >( __LINE__, __FILE__, "%", result_type::GLOBAL_FAILURE, 1 );
         verify_rule< must< minus< alnum, digit > > >( __LINE__, __FILE__, "1", result_type::GLOBAL_FAILURE, 0 );

         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "1", result_type::LOCAL_FAILURE, 1 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "%", result_type::LOCAL_FAILURE, 1 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "a%", result_type::SUCCESS, 1 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "a1", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "1a", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "11", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, digit > >( __LINE__, __FILE__, "%%", result_type::LOCAL_FAILURE, 2 );

         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "1", result_type::LOCAL_FAILURE, 1 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "%", result_type::LOCAL_FAILURE, 1 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "a%", result_type::SUCCESS, 1 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "aaa", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "aaa%", result_type::SUCCESS, 1 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "111", result_type::LOCAL_FAILURE, 3 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "111%", result_type::LOCAL_FAILURE, 4 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "a1a", result_type::SUCCESS, 0 );
         verify_rule< minus< plus< alnum >, plus< digit > > >( __LINE__, __FILE__, "1a1", result_type::SUCCESS, 0 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
