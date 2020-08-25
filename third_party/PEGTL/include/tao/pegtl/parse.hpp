// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_PARSE_HPP
#define TAOCPP_PEGTL_INCLUDE_PARSE_HPP

#include "apply_mode.hpp"
#include "config.hpp"
#include "normal.hpp"
#include "nothing.hpp"
#include "parse_error.hpp"
#include "rewind_mode.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule,
                template< typename... > class Action = nothing,
                template< typename... > class Control = normal,
                apply_mode A = apply_mode::ACTION,
                rewind_mode M = rewind_mode::REQUIRED,
                typename Input,
                typename... States >
      bool parse( Input&& in, States&&... st )
      {
         return Control< Rule >::template match< A, M, Action, Control >( in, st... );
      }

      template< typename Rule,
                template< typename... > class Action = nothing,
                template< typename... > class Control = normal,
                apply_mode A = apply_mode::ACTION,
                rewind_mode M = rewind_mode::REQUIRED,
                typename Outer,
                typename Input,
                typename... States >
      bool parse_nested( const Outer& oi, Input&& in, States&&... st )
      {
         try {
            return parse< Rule, Action, Control, A, M >( in, st... );
         }
         catch( parse_error& e ) {
            e.positions.push_back( oi.position() );
            throw;
         }
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
