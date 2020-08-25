// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_APPLY_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_APPLY_HPP

#include "../config.hpp"

#include "skip_control.hpp"
#include "trivial.hpp"

#include "../analysis/counted.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< apply_mode A, typename... Actions >
         struct apply_impl;

         template< typename... Actions >
         struct apply_impl< apply_mode::ACTION, Actions... >
         {
            template< typename Input, typename... States >
            static bool match( Input& in, States&&... st )
            {
               using action_t = typename Input::action_t;
               const action_t i2( in.iterator(), in );  // No data -- range is from begin to begin.
#ifdef __cpp_fold_expressions
               ( Actions::apply( i2, st... ), ... );
#else
               using swallow = bool[];
               (void)swallow{ ( Actions::apply( i2, st... ), true )..., true };
#endif
               return true;
            }
         };

         template< typename... Actions >
         struct apply_impl< apply_mode::NOTHING, Actions... >
         {
            template< typename Input, typename... States >
            static bool match( Input&, States&&... )
            {
               return true;
            }
         };

         template< typename... Actions >
         struct apply
         {
            using analyze_t = analysis::counted< analysis::rule_type::ANY, 0 >;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               return apply_impl< A, Actions... >::match( in, st... );
            }
         };

         template< typename... Actions >
         struct skip_control< apply< Actions... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
