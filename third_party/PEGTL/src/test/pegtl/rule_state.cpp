// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include "verify_seqs.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      struct test_state_state
      {
         template< typename Input >
         explicit test_state_state( const Input& /*unused*/ )
         {
         }

         template< typename Input >
         void success( const Input& /*unused*/ ) const
         {
         }
      };

      struct test_state_with_template_parameters_state
      {
         template< typename Input >
         explicit test_state_with_template_parameters_state( const Input& /*unused*/ )
         {
         }

         template< apply_mode,
                   rewind_mode,
                   template< typename... > class Action,
                   template< typename... > class Control,
                   typename Input >
         void success( const Input& /*unused*/ ) const
         {
         }
      };

      template< typename... Rules >
      using test_state_rule = state< test_state_state, Rules... >;

      template< typename... Rules >
      using test_state_with_template_parameters_rule = state< test_state_with_template_parameters_state, Rules... >;

      void unit_test()
      {
         verify_seqs< test_state_rule >();
         verify_seqs< test_state_with_template_parameters_rule >();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
