// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include "verify_seqs.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace test1
      {
         struct action_a
         {
            template< typename Input >
            static void apply( const Input& in, std::string& r, std::string& s )
            {
               TAOCPP_PEGTL_TEST_ASSERT( r.empty() );
               TAOCPP_PEGTL_TEST_ASSERT( s.empty() );
               r += in.string();
            }
         };

         struct action_b
         {
            template< typename Input >
            static void apply( const Input& in, std::string& r, std::string& s )
            {
               TAOCPP_PEGTL_TEST_ASSERT( s.empty() );
               s += in.string();
               s += "*";
               s += r;
            }
         };

         template< typename Rule >
         struct action : nothing< Rule >
         {
         };

         int flag = 0;

         template<>
         struct action< one< '-' > >
         {
            static void apply0( std::string& /*unused*/, std::string& /*unused*/ )
            {
               ++flag;
            }
         };

      }  // namespace test1

      template< typename... Rules >
      using if_apply_seq = if_apply< seq< Rules... > >;

      template< typename... Rules >
      using if_apply_disable = if_apply< disable< Rules... > >;

      void unit_test()
      {
         std::string state_r;
         std::string state_s;
         TAOCPP_PEGTL_TEST_ASSERT( test1::flag == 0 );
         memory_input<> in1( "-", __FUNCTION__ );
         parse< must< if_apply< one< '-' >, test1::action_a, test1::action_b > >, test1::action >( in1, state_r, state_s );
         TAOCPP_PEGTL_TEST_ASSERT( test1::flag == 1 );
         TAOCPP_PEGTL_TEST_ASSERT( state_r == "-" );
         TAOCPP_PEGTL_TEST_ASSERT( state_s == "-*-" );
         memory_input<> in2( "-", __FUNCTION__ );
         parse< must< disable< if_apply< one< '-' >, test1::action_a, test1::action_b > > >, test1::action >( in2, state_r, state_s );
         TAOCPP_PEGTL_TEST_ASSERT( test1::flag == 1 );
         TAOCPP_PEGTL_TEST_ASSERT( state_r == "-" );
         TAOCPP_PEGTL_TEST_ASSERT( state_s == "-*-" );

         verify_seqs< if_apply_seq >();
         verify_seqs< if_apply_disable >();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
