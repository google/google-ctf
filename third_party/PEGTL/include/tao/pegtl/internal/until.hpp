// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_UNTIL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_UNTIL_HPP

#include "../config.hpp"

#include "bytes.hpp"
#include "eof.hpp"
#include "not_at.hpp"
#include "rule_conjunction.hpp"
#include "skip_control.hpp"
#include "star.hpp"

#include "../apply_mode.hpp"
#include "../rewind_mode.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Cond, typename... Rules >
         struct until;

         template< typename Cond >
         struct until< Cond >
         {
            using analyze_t = analysis::generic< analysis::rule_type::SEQ, star< not_at< Cond >, not_at< eof >, bytes< 1 > >, Cond >;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               auto m = in.template mark< M >();

               while( !Control< Cond >::template match< A, rewind_mode::REQUIRED, Action, Control >( in, st... ) ) {
                  if( in.empty() ) {
                     return false;
                  }
                  in.bump();
               }
               return m( true );
            }
         };

         template< typename Cond, typename... Rules >
         struct until
         {
            using analyze_t = analysis::generic< analysis::rule_type::SEQ, star< not_at< Cond >, not_at< eof >, Rules... >, Cond >;

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

               while( !Control< Cond >::template match< A, rewind_mode::REQUIRED, Action, Control >( in, st... ) ) {
                  if( in.empty() || ( !rule_conjunction< Rules... >::template match< A, m_t::next_rewind_mode, Action, Control >( in, st... ) ) ) {
                     return false;
                  }
               }
               return m( true );
            }
         };

         template< typename Cond, typename... Rules >
         struct skip_control< until< Cond, Rules... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
