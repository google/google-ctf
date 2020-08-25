// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_APPLY0_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_APPLY0_HPP

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
         struct apply0_impl;

         template< typename... Actions >
         struct apply0_impl< apply_mode::ACTION, Actions... >
         {
            template< typename... States >
            static bool match( States&&... st )
            {
#ifdef __cpp_fold_expressions
               ( Actions::apply0( st... ), ... );
#else
               using swallow = bool[];
               (void)swallow{ ( Actions::apply0( st... ), true )..., true };
#endif
               return true;
            }
         };

         template< typename... Actions >
         struct apply0_impl< apply_mode::NOTHING, Actions... >
         {
            template< typename... States >
            static bool match( States&&... )
            {
               return true;
            }
         };

         template< typename... Actions >
         struct apply0
         {
            using analyze_t = analysis::counted< analysis::rule_type::ANY, 0 >;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input&, States&&... st )
            {
               return apply0_impl< A, Actions... >::match( st... );
            }
         };

         template< typename... Actions >
         struct skip_control< apply0< Actions... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
