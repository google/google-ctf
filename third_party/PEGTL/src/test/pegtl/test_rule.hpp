// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_TEST_RULE_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_TEST_RULE_HPP

#include <tao/pegtl.hpp>

#include "test_assert.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< unsigned Size, apply_mode B, rewind_mode N, typename... Rules >
      struct test_rule
      {
         using analyze_t = typename seq< Rules... >::analyze_t;

         template< apply_mode A,
                   rewind_mode M,
                   template< typename... > class Action,
                   template< typename... > class Control,
                   typename Input,
                   typename... States >
         static bool match( Input& in, States&&... st )
         {
            static_assert( A == B, "unexpected apply mode" );
            static_assert( M == N, "unexpected rewind mode" );

            TAOCPP_PEGTL_TEST_ASSERT( in.size() == Size );

            return seq< Rules... >::template match< A, M, Action, Control >( in, st... );
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
