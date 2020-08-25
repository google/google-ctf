// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_ONE_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_ONE_HPP

#include <algorithm>
#include <utility>

#include "../config.hpp"

#include "bump_help.hpp"
#include "result_on_found.hpp"
#include "skip_control.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Char >
         bool contains( const Char c, const std::initializer_list< Char >& l ) noexcept
         {
            return std::find( l.begin(), l.end(), c ) != l.end();
         }

         template< result_on_found R, typename Peek, typename Peek::data_t... Cs >
         struct one
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< typename Input >
            static bool match( Input& in )
            {
               if( !in.empty() ) {
                  if( const auto t = Peek::peek( in ) ) {
                     if( contains( t.data, { Cs... } ) == bool( R ) ) {
                        bump_help< R, Input, typename Peek::data_t, Cs... >( in, t.size );
                        return true;
                     }
                  }
               }
               return false;
            }
         };

         template< result_on_found R, typename Peek, typename Peek::data_t C >
         struct one< R, Peek, C >
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< typename Input >
            static bool match( Input& in )
            {
               if( !in.empty() ) {
                  if( const auto t = Peek::peek( in ) ) {
                     if( ( t.data == C ) == bool( R ) ) {
                        bump_help< R, Input, typename Peek::data_t, C >( in, t.size );
                        return true;
                     }
                  }
               }
               return false;
            }
         };

         template< result_on_found R, typename Peek, typename Peek::data_t... Cs >
         struct skip_control< one< R, Peek, Cs... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
