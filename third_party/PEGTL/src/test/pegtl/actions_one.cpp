// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace test1
      {
         struct fiz : if_must< at< one< 'a' > >, two< 'a' > >
         {
         };

         struct foo : sor< fiz, one< 'b' > >
         {
         };

         struct bar : until< eof, foo >
         {
         };

         void test_result()
         {
            TAOCPP_PEGTL_TEST_ASSERT( applied.size() == 10 );

            TAOCPP_PEGTL_TEST_ASSERT( applied[ 0 ].first == internal::demangle< one< 'b' > >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 1 ].first == internal::demangle< foo >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 2 ].first == internal::demangle< at< one< 'a' > > >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 3 ].first == internal::demangle< two< 'a' > >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 4 ].first == internal::demangle< fiz >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 5 ].first == internal::demangle< foo >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 6 ].first == internal::demangle< one< 'b' > >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 7 ].first == internal::demangle< foo >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 8 ].first == internal::demangle< eof >() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 9 ].first == internal::demangle< bar >() );

            TAOCPP_PEGTL_TEST_ASSERT( applied[ 0 ].second == "b" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 1 ].second == "b" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 2 ].second.empty() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 3 ].second == "aa" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 4 ].second == "aa" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 5 ].second == "aa" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 6 ].second == "b" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 7 ].second == "b" );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 8 ].second.empty() );
            TAOCPP_PEGTL_TEST_ASSERT( applied[ 9 ].second == "baab" );
         }

      }  // namespace test1

      void unit_test()
      {
         parse< disable< test1::bar >, test_action >( memory_input<>( "baab", __FUNCTION__ ) );
         TAOCPP_PEGTL_TEST_ASSERT( applied.size() == 1 );

         TAOCPP_PEGTL_TEST_ASSERT( applied[ 0 ].first == internal::demangle< disable< test1::bar > >() );
         TAOCPP_PEGTL_TEST_ASSERT( applied[ 0 ].second == "baab" );

         applied.clear();

         parse< at< action< test_action, test1::bar > > >( memory_input<>( "baab", __FUNCTION__ ) );

         TAOCPP_PEGTL_TEST_ASSERT( applied.empty() );

         applied.clear();

         parse< test1::bar, test_action >( memory_input<>( "baab", __FUNCTION__ ) );

         test1::test_result();

         applied.clear();

         parse< action< test_action, test1::bar > >( memory_input<>( "baab", __FUNCTION__ ) );

         test1::test_result();

         applied.clear();

         parse< disable< enable< action< test_action, test1::bar > > > >( memory_input<>( "baab", __FUNCTION__ ) );

         test1::test_result();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
