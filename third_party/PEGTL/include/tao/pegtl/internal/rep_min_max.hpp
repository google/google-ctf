// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_MIN_MAX_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_MIN_MAX_HPP

#include <type_traits>

#include "../config.hpp"

#include "duseltronik.hpp"
#include "not_at.hpp"
#include "rule_conjunction.hpp"
#include "seq.hpp"
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
         template< unsigned Min, unsigned Max, typename... Rules >
         struct rep_min_max;

         template< unsigned Min, unsigned Max >
         struct rep_min_max< Min, Max >
            : trivial< false >
         {
            static_assert( Min <= Max, "invalid rep_min_max rule (maximum number of repetitions smaller than minimum)" );
         };

         template< typename Rule, typename... Rules >
         struct rep_min_max< 0, 0, Rule, Rules... >
            : not_at< Rule, Rules... >
         {
         };

         template< unsigned Min, unsigned Max, typename... Rules >
         struct rep_min_max
         {
            using analyze_t = analysis::counted< analysis::rule_type::SEQ, Min, Rules... >;

            static_assert( Min <= Max, "invalid rep_min_max rule (maximum number of repetitions smaller than minimum)" );

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

               for( unsigned i = 0; i != Min; ++i ) {
                  if( !rule_conjunction< Rules... >::template match< A, m_t::next_rewind_mode, Action, Control >( in, st... ) ) {
                     return false;
                  }
               }
               for( unsigned i = Min; i != Max; ++i ) {
                  if( !duseltronik< seq< Rules... >, A, rewind_mode::REQUIRED, Action, Control >::match( in, st... ) ) {
                     return m( true );
                  }
               }
               return m( duseltronik< not_at< Rules... >, A, m_t::next_rewind_mode, Action, Control >::match( in, st... ) );  // NOTE that not_at<> will always rewind.
            }
         };

         template< unsigned Min, unsigned Max, typename... Rules >
         struct skip_control< rep_min_max< Min, Max, Rules... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
