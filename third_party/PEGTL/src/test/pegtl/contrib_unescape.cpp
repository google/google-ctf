// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/contrib/unescape.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      // clang-format off
      struct escaped_c : one< '"', '\\', 't' > {};
      struct escaped_u : seq< one< 'u' >, rep< 4, must< xdigit > > > {};
      struct escaped_U : seq< one< 'U' >, rep< 8, must< xdigit > > > {};
      struct escaped_j : list< seq< one< 'j' >, rep< 4, must< xdigit > > >, one< '\\' > > {};
      struct escaped_x : seq< one< 'x' >, rep< 2, must< xdigit > > > {};
      struct escaped : sor< escaped_c, escaped_u, escaped_U, escaped_j, escaped_x > {};
      struct character : if_then_else< one< '\\' >, must< escaped >, utf8::any > {};
      struct unstring : until< eof, character > {};

      template< typename Rule > struct unaction : nothing< Rule > {};

      template<> struct unaction< escaped_c > : unescape::unescape_c< escaped_c, '"', '\\', '\t' > {};
      template<> struct unaction< escaped_u > : unescape::unescape_u {};
      template<> struct unaction< escaped_U > : unescape::unescape_u {};
      template<> struct unaction< escaped_j > : unescape::unescape_j {};
      template<> struct unaction< escaped_x > : unescape::unescape_x {};
      template<> struct unaction< utf8::any > : unescape::append_all {};
      // clang-format on

      template< unsigned M, unsigned N >
      void verify_data( const char ( &m )[ M ], const char ( &n )[ N ] )
      {
         unescape::state st;
         memory_input<> in( m, M - 1, __FUNCTION__ );
         parse< unstring, unaction >( in, st );
         if( st.unescaped != std::string( n, N - 1 ) ) {
            throw std::runtime_error( "test failed!" );
         }
      }

      void unit_test()
      {
         verify_data( "\\t", "\t" );
         verify_data( "\\\\", "\\" );
         verify_data( "abc", "abc" );
         verify_data( "\\\"foo\\\"", "\"foo\"" );
         verify_data( "\\x20", " " );
         verify_data( "\\x30", "0" );
         verify_data( "\\x2000", " 00" );
         verify_data( "\\u0020", " " );
         verify_data( "\\u0020\\u0020", "  " );
         verify_data( "\\u00e4", "\xc3\xa4" );
         verify_data( "\\u00E4", "\xC3\xA4" );
         verify_data( "\\u20ac", "\xe2\x82\xac" );
         verify_data( "\\ud800\\u0020", "\xed\xa0\x80 " );
         verify_data( "\\ud800\\udc00", "\xed\xa0\x80\xed\xb0\x80" );
         verify_data( "\\j0020", " " );
         verify_data( "\\j0020\\j0020", "  " );
         verify_data( "\\j20ac", "\xe2\x82\xac" );
         verify_data( "\\jd800\\j0020", "\xed\xa0\x80 " );
         verify_data( "\\jd800\\jdc00", "\xf0\x90\x80\x80" );
         verify_data( "\\j0000\\u0000\x00", "\x00\x00\x00" );
         unescape::state st;
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\\\\\", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\x", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\xx", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\xa", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\x1", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\x1h", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "a\\", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "a\\x", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "a\\xx", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "a\\xa", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "a\\x1", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "a\\x1h", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\a", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\_", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\z", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\1", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\a00", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\_1111", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\z22222222", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\13333333333333333", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\u", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\uu", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\uuuu", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\u123", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\u999", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\u444h", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\j", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\ju", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\juuu", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\j123", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\j999", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\j444h", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\U00110000", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\U80000000", st );
         verify_fail< unstring, unaction >( __LINE__, __FILE__, "\\Uffffffff", st );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
