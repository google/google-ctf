// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_RANGE_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_RANGE_HPP

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
         template< result_on_found R, typename Peek, typename Peek::data_t Lo, typename Peek::data_t Hi >
         struct range
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< int Eol >
            struct can_match_eol
            {
               static constexpr bool value = ( ( ( Lo <= Eol ) && ( Eol <= Hi ) ) == bool( R ) );
            };

            template< typename Input >
            static bool match( Input& in )
            {
               using eol_t = typename Input::eol_t;

               if( !in.empty() ) {
                  if( const auto t = Peek::peek( in ) ) {
                     if( ( ( Lo <= t.data ) && ( t.data <= Hi ) ) == bool( R ) ) {
                        bump_impl< can_match_eol< eol_t::ch >::value >::bump( in, t.size );
                        return true;
                     }
                  }
               }
               return false;
            }
         };

         template< result_on_found R, typename Peek, typename Peek::data_t Lo, typename Peek::data_t Hi >
         struct skip_control< range< R, Peek, Lo, Hi > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
