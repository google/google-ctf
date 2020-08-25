// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace test1
      {
         struct state1
         {
            char c;

            template< typename Input >
            state1( const Input& /*unused*/, std::string& /*unused*/ )
               : c()
            {
            }

            template< typename Input >
            void success( const Input& /*unused*/, std::string& s ) const
            {
               s += c;
            }
         };

         struct fobble : sor< state< state1, alpha >, digit >
         {
         };

         struct fibble : until< eof, fobble >
         {
         };

         template< typename Rule >
         struct action1 : nothing< Rule >
         {
         };

         template<>
         struct action1< alpha >
         {
            template< typename Input >
            static void apply( const Input& in, state1& s )
            {
               assert( in.size() == 1 );
               s.c = in.begin()[ 0 ];
            }
         };

         void state_test()
         {
            std::string result;
            memory_input<> in( "dk41sk41xk3", __FUNCTION__ );
            parse< fibble, action1 >( in, result );
            TAOCPP_PEGTL_TEST_ASSERT( result == "dkskxk" );
         }

         template< typename Rule >
         struct action0 : nothing< Rule >
         {
         };

         static int i0 = 0;

         template<>
         struct action0< alpha >
         {
            static void apply0()
            {
               ++i0;
            }
         };

         template<>
         struct action0< digit >
         {
            static void apply0( std::string& s )
            {
               s += '0';
            }
         };

         void apply0_test()
         {
            memory_input<> ina( "abcdefgh", __FUNCTION__ );
            parse< star< alpha >, action0 >( ina );
            TAOCPP_PEGTL_TEST_ASSERT( i0 == 8 );
            std::string s0;
            memory_input<> ind( "12345678", __FUNCTION__ );
            parse< star< digit >, action0 >( ind, s0 );
            TAOCPP_PEGTL_TEST_ASSERT( s0 == "00000000" );
         }

         const std::size_t count_byte = 12345;
         const std::size_t count_line = 42;
         const std::size_t count_byte_in_line = 12;

         const char* count_source = "count_source";

         template< typename Rule >
         struct count_action
         {
            template< typename Input >
            static void apply( const Input& in )
            {
               TAOCPP_PEGTL_TEST_ASSERT( in.iterator().byte == count_byte );
               TAOCPP_PEGTL_TEST_ASSERT( in.iterator().line == count_line );
               TAOCPP_PEGTL_TEST_ASSERT( in.iterator().byte_in_line == count_byte_in_line );
               TAOCPP_PEGTL_TEST_ASSERT( in.input().source() == count_source );
               TAOCPP_PEGTL_TEST_ASSERT( in.size() == 1 );
               TAOCPP_PEGTL_TEST_ASSERT( in.begin() + 1 == in.end() );
               TAOCPP_PEGTL_TEST_ASSERT( in.peek_char() == 'f' );
               TAOCPP_PEGTL_TEST_ASSERT( in.peek_byte() == static_cast< unsigned char >( 'f' ) );
            }
         };

         void count_test()
         {
            const char* foo = "f";
            memory_input<> in( foo, foo + 1, count_source, count_byte, count_line, count_byte_in_line );
            const auto result = parse< must< alpha >, count_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( result );
         }

      }  // namespace test1

      void unit_test()
      {
         test1::state_test();
         test1::apply0_test();
         test1::count_test();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
