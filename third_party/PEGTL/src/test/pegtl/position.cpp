// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/internal/cstring_reader.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      struct buffer_input_t
         : buffer_input< internal::cstring_reader >
      {
         buffer_input_t( const std::string& in_string, const std::string& in_source )
            : buffer_input< internal::cstring_reader >( in_source, 42, in_string.c_str() )
         {
         }
      };

      template< typename Rule, typename Input = memory_input<> >
      void test_matches_lf()
      {
         static const std::string s1 = "\n";

         Input i1( s1, __FUNCTION__ );

         TAOCPP_PEGTL_TEST_ASSERT( parse< Rule >( i1 ) );
         TAOCPP_PEGTL_TEST_ASSERT( i1.line() == 2 );
         TAOCPP_PEGTL_TEST_ASSERT( i1.byte_in_line() == 0 );
      }

      template< typename Rule, typename Input = memory_input<> >
      void test_matches_other( const std::string& s2 )
      {
         TAOCPP_PEGTL_TEST_ASSERT( s2.size() == 1 );

         Input i2( s2, __FUNCTION__ );

         TAOCPP_PEGTL_TEST_ASSERT( parse< Rule >( i2 ) );
         TAOCPP_PEGTL_TEST_ASSERT( i2.line() == 1 );
         TAOCPP_PEGTL_TEST_ASSERT( i2.byte_in_line() == 1 );
      }

      template< typename Rule, typename Input = memory_input<> >
      void test_mismatch( const std::string& s3 )
      {
         TAOCPP_PEGTL_TEST_ASSERT( s3.size() == 1 );

         Input i3( s3, __FUNCTION__ );

         TAOCPP_PEGTL_TEST_ASSERT( !parse< Rule >( i3 ) );
         TAOCPP_PEGTL_TEST_ASSERT( i3.line() == 1 );
         TAOCPP_PEGTL_TEST_ASSERT( i3.byte_in_line() == 0 );
      }

      struct outer_grammar
         : must< two< 'a' >, two< 'b' >, two< 'c' >, eof >
      {
      };

      struct inner_grammar
         : must< one< 'd' >, two< 'e' >, eof >
      {
      };

      template< typename Rule >
      struct outer_action
         : nothing< Rule >
      {
      };

      template<>
      struct outer_action< two< 'b' > >
      {
         template< typename Input >
         static void apply( const Input& oi )
         {
            const auto p = oi.position();
            TAOCPP_PEGTL_TEST_ASSERT( p.source == "outer" );
            TAOCPP_PEGTL_TEST_ASSERT( p.byte == 2 );
            TAOCPP_PEGTL_TEST_ASSERT( p.line == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( p.byte_in_line == 2 );
            memory_input<> in( "dFF", "inner" );
            parse_nested< inner_grammar >( oi, in );
         }
      };

      template< typename Input = memory_input<> >
      void test_nested()
      {
         try {
            memory_input<> oi( "aabbcc", "outer" );
            parse< outer_grammar, outer_action >( oi );
         }
         catch( const parse_error& e ) {
            TAOCPP_PEGTL_TEST_ASSERT( e.positions.size() == 2 );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 0 ].source == "inner" );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 0 ].byte == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 0 ].line == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 0 ].byte_in_line == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 1 ].source == "outer" );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 1 ].byte == 2 );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 1 ].line == 1 );
            TAOCPP_PEGTL_TEST_ASSERT( e.positions[ 1 ].byte_in_line == 2 );
         }
      }

      void unit_test()
      {
         test_matches_lf< any >();
         test_matches_lf< any, buffer_input_t >();
         test_matches_other< any >( " " );
         test_matches_other< any, buffer_input_t >( " " );

         test_matches_lf< one< '\n' > >();
         test_matches_lf< one< '\n' >, buffer_input_t >();
         test_mismatch< one< '\n' > >( " " );
         test_mismatch< one< '\n' >, buffer_input_t >( " " );

         test_matches_lf< one< ' ', '\n' > >();
         test_matches_lf< one< ' ', '\n' >, buffer_input_t >();
         test_matches_other< one< ' ', '\n' > >( " " );
         test_matches_other< one< ' ', '\n' >, buffer_input_t >( " " );

         test_matches_lf< one< ' ', '\n', 'b' > >();
         test_matches_lf< one< ' ', '\n', 'b' >, buffer_input_t >();
         test_matches_other< one< ' ', '\n', 'b' > >( " " );
         test_matches_other< one< ' ', '\n', 'b' >, buffer_input_t >( " " );

         test_matches_lf< string< '\n' > >();
         test_matches_lf< string< '\n' >, buffer_input_t >();
         test_mismatch< string< '\n' > >( " " );
         test_mismatch< string< '\n' >, buffer_input_t >( " " );

         test_matches_other< string< ' ' > >( " " );
         test_matches_other< string< ' ' >, buffer_input_t >( " " );
         test_mismatch< string< ' ' > >( "\n" );
         test_mismatch< string< ' ' >, buffer_input_t >( "\n" );

         test_matches_lf< range< 8, 33 > >();
         test_matches_lf< range< 8, 33 >, buffer_input_t >();
         test_matches_other< range< 8, 33 > >( " " );
         test_matches_other< range< 8, 33 >, buffer_input_t >( " " );

         test_mismatch< range< 11, 30 > >( "\n" );
         test_mismatch< range< 11, 30 >, buffer_input_t >( "\n" );
         test_mismatch< range< 11, 30 > >( " " );
         test_mismatch< range< 11, 30 >, buffer_input_t >( " " );

         test_matches_lf< not_range< 20, 30 > >();
         test_matches_lf< not_range< 20, 30 >, buffer_input_t >();
         test_matches_other< not_range< 20, 30 > >( " " );
         test_matches_other< not_range< 20, 30 >, buffer_input_t >( " " );

         test_mismatch< not_range< 5, 35 > >( "\n" );
         test_mismatch< not_range< 5, 35 >, buffer_input_t >( "\n" );
         test_mismatch< not_range< 5, 35 > >( " " );
         test_mismatch< not_range< 5, 35 >, buffer_input_t >( " " );

         test_matches_lf< ranges< 'a', 'z', 8, 33, 'A', 'Z' > >();
         test_matches_lf< ranges< 'a', 'z', 8, 33, 'A', 'Z' >, buffer_input_t >();
         test_matches_other< ranges< 'a', 'z', 8, 33, 'A', 'Z' > >( "N" );
         test_mismatch< ranges< 'a', 'z', 8, 33, 'A', 'Z' > >( "9" );
         test_mismatch< ranges< 'a', 'z', 8, 33, 'A', 'Z' >, buffer_input_t >( "9" );

         test_matches_lf< ranges< 'a', 'z', 'A', 'Z', '\n' > >();
         test_matches_lf< ranges< 'a', 'z', 'A', 'Z', '\n' >, buffer_input_t >();
         test_matches_other< ranges< 'a', 'z', 'A', 'Z', '\n' > >( "P" );
         test_matches_other< ranges< 'a', 'z', 'A', 'Z', '\n' >, buffer_input_t >( "P" );
         test_mismatch< ranges< 'a', 'z', 'A', 'Z', '\n' > >( "8" );
         test_mismatch< ranges< 'a', 'z', 'A', 'Z', '\n' >, buffer_input_t >( "8" );

         test_nested<>();
         test_nested< buffer_input_t >();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
