// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace test1
      {
         bool apply_result;

         struct grammar
            : test_rule< 2, apply_mode::ACTION, rewind_mode::ACTIVE, any >
         {
         };

         template< typename Rule >
         struct apply_bool_action : nothing< Rule >
         {
         };

         template<>
         struct apply_bool_action< grammar >
         {
            template< typename Input >
            static bool apply( const Input& /*unused*/ )
            {
               return apply_result;
            }
         };

         void apply_bool_true()
         {
            apply_result = true;
            memory_input<> in( "ab", __FUNCTION__ );
            const auto result = parse< grammar, apply_bool_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( result );
            TAOCPP_PEGTL_TEST_ASSERT( in.size() == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( in.peek_char() == 'b' );
         }

         void apply_bool_false()
         {
            apply_result = false;
            memory_input<> in( "ab", __FUNCTION__ );
            const auto result = parse< grammar, apply_bool_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( !result );
            TAOCPP_PEGTL_TEST_ASSERT( in.size() == 2 );
            TAOCPP_PEGTL_TEST_ASSERT( in.peek_char() == 'a' );
         }

         template< typename Rule >
         struct apply0_bool_action : nothing< Rule >
         {
         };

         template<>
         struct apply0_bool_action< grammar >
         {
            static bool apply0()
            {
               return apply_result;
            }
         };

         void apply0_bool_true()
         {
            apply_result = true;
            memory_input<> in( "ab", __FUNCTION__ );
            const auto result = parse< grammar, apply0_bool_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( result );
            TAOCPP_PEGTL_TEST_ASSERT( in.size() == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( in.peek_char() == 'b' );
         }

         void apply0_bool_false()
         {
            apply_result = false;
            memory_input<> in( "ab", __FUNCTION__ );
            const auto result = parse< grammar, apply0_bool_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( !result );
            TAOCPP_PEGTL_TEST_ASSERT( in.size() == 2 );
            TAOCPP_PEGTL_TEST_ASSERT( in.peek_char() == 'a' );
         }

      }  // namespace test1

      void unit_test()
      {
         test1::apply_bool_true();
         test1::apply_bool_false();
         test1::apply0_bool_true();
         test1::apply0_bool_false();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
