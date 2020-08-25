// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_VERIFY_IFMT_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_VERIFY_IFMT_HPP

#include <tao/pegtl.hpp>

#include "verify_analyze.hpp"
#include "verify_rule.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< template< typename, typename, typename > class S >
      void verify_ifmt( const result_type failure = result_type::LOCAL_FAILURE )
      {
         verify_analyze< S< eof, eof, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< S< eof, eof, any > >( __LINE__, __FILE__, false, false );
         verify_analyze< S< eof, any, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< S< eof, any, any > >( __LINE__, __FILE__, true, false );
         verify_analyze< S< any, eof, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< S< any, eof, any > >( __LINE__, __FILE__, true, false );
         verify_analyze< S< any, any, eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< S< any, any, any > >( __LINE__, __FILE__, true, false );

         verify_rule< S< one< 'a' >, one< 'b' >, one< 'c' > > >( __LINE__, __FILE__, "", failure, 0 );
         verify_rule< S< one< 'a' >, one< 'b' >, one< 'c' > > >( __LINE__, __FILE__, "b", failure, 1 );
         verify_rule< S< one< 'a' >, one< 'b' >, one< 'c' > > >( __LINE__, __FILE__, "c", result_type::SUCCESS, 0 );
         verify_rule< S< one< 'a' >, one< 'b' >, one< 'c' > > >( __LINE__, __FILE__, "ab", result_type::SUCCESS, 0 );
         verify_rule< S< one< 'a' >, one< 'b' >, one< 'c' > > >( __LINE__, __FILE__, "ac", failure, 2 );

         verify_rule< must< S< one< 'a' >, one< 'b' >, one< 'c' > > > >( __LINE__, __FILE__, "", result_type::GLOBAL_FAILURE, 0 );
         verify_rule< must< S< one< 'a' >, one< 'b' >, one< 'c' > > > >( __LINE__, __FILE__, "a", result_type::GLOBAL_FAILURE, 0 );
         verify_rule< must< S< one< 'a' >, one< 'b' >, one< 'c' > > > >( __LINE__, __FILE__, "ac", result_type::GLOBAL_FAILURE, 1 );
         verify_rule< must< S< one< 'a' >, one< 'b' >, one< 'c' > > > >( __LINE__, __FILE__, "b", result_type::GLOBAL_FAILURE, 1 );

         verify_rule< must< S< one< 'a' >, one< 'b' >, seq< one< 'c' >, one< 'd' > > > > >( __LINE__, __FILE__, "c", result_type::GLOBAL_FAILURE, 0 );
         verify_rule< must< S< one< 'a' >, one< 'b' >, seq< one< 'c' >, one< 'd' > > > > >( __LINE__, __FILE__, "cc", result_type::GLOBAL_FAILURE, 1 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
