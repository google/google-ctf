// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_HPP

#include "../config.hpp"

#include "rule_conjunction.hpp"
#include "skip_control.hpp"
#include "trivial.hpp"

#include "../apply_mode.hpp"
#include "../rewind_mode.hpp"

#include "../analysis/counted.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< unsigned Num, typename... Rules >
         struct rep;

         template< unsigned Num >
         struct rep< Num >
            : trivial< true >
         {
         };

         template< typename Rule, typename... Rules >
         struct rep< 0, Rule, Rules... >
            : trivial< true >
         {
         };

         template< unsigned Num, typename... Rules >
         struct rep
         {
            using analyze_t = analysis::counted< analysis::rule_type::SEQ, Num, Rules... >;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               auto m = in.template mark< M >();
               using m_t = decltype( m );

               for( unsigned i = 0; i != Num; ++i ) {
                  if( !rule_conjunction< Rules... >::template match< A, m_t::next_rewind_mode, Action, Control >( in, st... ) ) {
                     return false;
                  }
               }
               return m( true );
            }
         };

         template< unsigned Num, typename... Rules >
         struct skip_control< rep< Num, Rules... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
