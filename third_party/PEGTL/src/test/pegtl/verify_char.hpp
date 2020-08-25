// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_VERIFY_CHAR_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_VERIFY_CHAR_HPP

#include <cstdlib>
#include <string>

#include "result_type.hpp"
#include "verify_rule.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule >
      void verify_char( const std::size_t line, const char* file, const char data, const result_type result )
      {
         verify_rule< Rule >( line, file, std::string( std::size_t( 1 ), data ), result, ( result == result_type::SUCCESS ) ? 0 : 1 );
      }

      template< typename Rule >
      void verify_char( const std::size_t line, const char* file, const char data, const bool result )
      {
         verify_char< Rule >( line, file, data, result ? result_type::SUCCESS : result_type::LOCAL_FAILURE );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
