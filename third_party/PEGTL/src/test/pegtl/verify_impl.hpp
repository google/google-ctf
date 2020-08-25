// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_VERIFY_IMPL_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_VERIFY_IMPL_HPP

#include <cstddef>
#include <stdexcept>
#include <string>

#include <tao/pegtl/apply_mode.hpp>
#include <tao/pegtl/normal.hpp>
#include <tao/pegtl/rewind_mode.hpp>

#include "result_type.hpp"
#include "test_failed.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule, template< typename... > class Action, typename Input >
      result_type verify_impl_two( Input& in )
      {
         try {
            if( normal< Rule >::template match< apply_mode::ACTION, rewind_mode::REQUIRED, Action, normal >( in ) ) {
               return result_type::SUCCESS;
            }
            return result_type::LOCAL_FAILURE;
         }
         catch( const std::exception& ) {
            return result_type::GLOBAL_FAILURE;
         }
         catch( ... ) {
            throw std::runtime_error( "code should be unreachable" );  // LCOV_EXCL_LINE
         }
      }

      template< typename Rule, template< typename... > class Action, typename Input >
      void verify_impl_one( const std::size_t line, const char* file, const std::string& data, Input& in, const result_type expected, const std::size_t remain )
      {
         const result_type received = verify_impl_two< Rule, Action >( in );

         if( ( received == expected ) && ( ( received == result_type::GLOBAL_FAILURE ) || ( in.size( 999999999 ) == remain ) ) ) {
            return;
         }
         TAOCPP_PEGTL_TEST_FAILED( "input data [ '" << data << "' ] result received/expected [ " << received << " / " << expected << " ] remain received/expected [ " << in.size( 999999999 ) << " / " << remain << " ]" );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
