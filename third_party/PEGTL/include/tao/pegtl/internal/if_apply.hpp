// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_IF_APPLY_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_IF_APPLY_HPP

#include "../config.hpp"

#include "skip_control.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< apply_mode A, typename Rule, typename... Actions >
         struct if_apply_impl;

         template< typename Rule, typename... Actions >
         struct if_apply_impl< apply_mode::ACTION, Rule, Actions... >
         {
            template< rewind_mode,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               using action_t = typename Input::action_t;

               auto m = in.template mark< rewind_mode::REQUIRED >();

               if( Control< Rule >::template match< apply_mode::ACTION, rewind_mode::ACTIVE, Action, Control >( in, st... ) ) {
                  const action_t i2( m.iterator(), in );
#ifdef __cpp_fold_expressions
                  ( Actions::apply( i2, st... ), ... );
#else
                  using swallow = bool[];
                  (void)swallow{ ( Actions::apply( i2, st... ), true )..., true };
#endif
                  return m( true );
               }
               return false;
            }
         };

         template< typename Rule, typename... Actions >
         struct if_apply_impl< apply_mode::NOTHING, Rule, Actions... >
         {
            template< rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               return Control< Rule >::template match< apply_mode::NOTHING, M, Action, Control >( in, st... );
            }
         };

         template< typename Rule, typename... Actions >
         struct if_apply
         {
            using analyze_t = typename Rule::analyze_t;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               return if_apply_impl< A, Rule, Actions... >::template match< M, Action, Control >( in, st... );
            }
         };

         template< typename Rule, typename... Actions >
         struct skip_control< if_apply< Rule, Actions... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
