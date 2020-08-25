// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< sor< eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< any > >( __LINE__, __FILE__, true, false );

         verify_analyze< sor< any, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< eof, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< eof, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< any, any > >( __LINE__, __FILE__, true, false );

         verify_analyze< sor< any, any, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< any, eof, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< any, eof, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< any, any, any > >( __LINE__, __FILE__, true, false );
         verify_analyze< sor< eof, any, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< eof, eof, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< eof, eof, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< sor< eof, any, any > >( __LINE__, __FILE__, false, false );

         verify_rule< sor<> >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< sor<> >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );

         verify_rule< sor< one< 'a' > > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< sor< one< 'a' > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< sor< one< 'a' > > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 1 );

         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 0 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "b", result_type::SUCCESS, 0 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "c", result_type::LOCAL_FAILURE, 1 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 1 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ab", result_type::SUCCESS, 1 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "ba", result_type::SUCCESS, 1 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "bb", result_type::SUCCESS, 1 );
         verify_rule< sor< one< 'a' >, one< 'b' > > >( __LINE__, __FILE__, "cb", result_type::LOCAL_FAILURE, 2 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
