// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_NORMAL_HPP
#define TAOCPP_PEGTL_INCLUDE_NORMAL_HPP

#include <utility>

#include "apply_mode.hpp"
#include "config.hpp"
#include "nothing.hpp"
#include "parse_error.hpp"
#include "rewind_mode.hpp"

#include "internal/demangle.hpp"
#include "internal/dusel_mode.hpp"
#include "internal/duseltronik.hpp"
#include "internal/has_apply.hpp"
#include "internal/has_apply0.hpp"
#include "internal/skip_control.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule >
      struct normal
      {
         template< typename Input, typename... States >
         static void start( const Input&, States&&... ) noexcept
         {
         }

         template< typename Input, typename... States >
         static void success( const Input&, States&&... ) noexcept
         {
         }

         template< typename Input, typename... States >
         static void failure( const Input&, States&&... ) noexcept
         {
         }

         template< typename Input, typename... States >
         static void raise( const Input& in, States&&... )
         {
            throw parse_error( "parse error matching " + internal::demangle< Rule >(), in );
         }

         template< template< typename... > class Action, typename Input, typename... States >
         static auto apply0( const Input&, States&&... st ) -> decltype( Action< Rule >::apply0( st... ) )
         {
            return Action< Rule >::apply0( st... );
         }

         template< template< typename... > class Action, typename Iterator, typename Input, typename... States >
         static auto apply( const Iterator& begin, const Input& in, States&&... st ) -> decltype( Action< Rule >::apply( std::declval< typename Input::action_t >(), st... ) )
         {
            using action_t = typename Input::action_t;
            const action_t action_input( begin, in );
            return Action< Rule >::apply( action_input, st... );
         }

         template< apply_mode A,
                   rewind_mode M,
                   template< typename... > class Action,
                   template< typename... > class Control,
                   typename Input,
                   typename... States >
         static bool match( Input& in, States&&... st )
         {
            constexpr char use_control = !internal::skip_control< Rule >::value;
            constexpr char use_action = use_control && ( A == apply_mode::ACTION ) && ( !is_nothing< Action, Rule >::value );
            constexpr char use_apply_void = use_action && internal::has_apply< Action< Rule >, void, typename Input::action_t, States... >::value;
            constexpr char use_apply_bool = use_action && internal::has_apply< Action< Rule >, bool, typename Input::action_t, States... >::value;
            constexpr char use_apply0_void = use_action && internal::has_apply0< Action< Rule >, void, States... >::value;
            constexpr char use_apply0_bool = use_action && internal::has_apply0< Action< Rule >, bool, States... >::value;
            static_assert( use_apply_void + use_apply_bool + use_apply0_void + use_apply0_bool < 2, "more than one apply or apply0 defined" );
            static_assert( !use_action || use_apply_bool || use_apply_void || use_apply0_bool || use_apply0_void, "actions not disabled but no apply or apply0 found" );
            constexpr dusel_mode mode = static_cast< dusel_mode >( use_control + use_apply_void + 2 * use_apply_bool + 3 * use_apply0_void + 4 * use_apply0_bool );
            return internal::duseltronik< Rule, A, M, Action, Control, mode >::match( in, st... );
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
