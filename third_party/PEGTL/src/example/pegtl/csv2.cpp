// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <iostream>
#include <utility>

#include <tao/pegtl.hpp>

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace csv2
{
   // Simple CSV-file format for a known-at-compile-time number of values per
   // line, the values are strings that can use quotes when they contain commas,
   // if quotes are used they have to be the first character (of the line or
   // after the comma); quoted strings can't contain quotes, no string can have
   // LF or CR; last line has to end with an LF or CR+LF.

   // Example file contents parsed by this grammar (excluding C++ comment intro):
   // a,b,c
   // "foo","bar","baz"
   // ",,,",13,42
   // aha """,yes, this works

   // clang-format off
   template< int C > struct string_without : pegtl::star< pegtl::not_one< C, 10, 13 > > {};
   struct plain_value : string_without< ',' > {};
   struct quoted_value : pegtl::if_must< pegtl::one< '"' >, string_without< '"' >, pegtl::one< '"' > > {};
   struct value : pegtl::sor< quoted_value, plain_value > {};
   template< unsigned N > struct line : pegtl::seq< value, pegtl::rep< N - 1, pegtl::one< ',' >, value >, pegtl::eol > {};
   template< unsigned N > struct file : pegtl::until< pegtl::eof, line< N > > { static_assert( N, "N must be positive" ); };
   // clang-format on

   // Meta-programming helper:

   template< unsigned N, typename T >
   struct tuple_help;

   template< unsigned N, typename... S >
   struct tuple_help< N, std::tuple< S... > >
   {
      using tuple_t = typename tuple_help< N - 1, std::tuple< std::string, S... > >::tuple_t;
   };

   template< typename... S >
   struct tuple_help< 0, std::tuple< S... > >
   {
      using tuple_t = std::tuple< S... >;
   };

   // Ad-hoc helper to initialise a tuple from a vector:

   template< unsigned I >
   struct tuple_init
   {
      template< typename... S >
      static void init( std::tuple< S... >& t, std::vector< std::string >& v )
      {
         std::get< I >( t ) = std::move( v[ I ] );
         tuple_init< I - 1 >::init( t, v );
      }
   };

   template<>
   struct tuple_init< 0 >
   {
      template< typename... S >
      static void init( std::tuple< S... >& t, std::vector< std::string >& v )
      {
         std::get< 0 >( t ) = std::move( v[ 0 ] );
      }
   };

   // Data structure to store the result of a parsing run:

   template< unsigned N >
   struct result_data
   {
      using tuple_t = typename tuple_help< N, std::tuple<> >::tuple_t;

      std::vector< std::string > temp;
      std::vector< tuple_t > result;
   };

   // Action class to fill in the above data structure:

   template< typename Rule >
   struct action : pegtl::nothing< Rule >
   {
   };

   template<>
   struct action< plain_value >
   {
      template< typename Input, unsigned N >
      static void apply( const Input& in, result_data< N >& data )
      {
         data.temp.push_back( in.string() );
      }
   };

   template<>
   struct action< string_without< '"' > >
      : action< plain_value >
   {
   };

   template< unsigned N >
   struct action< line< N > >
   {
      using tuple_t = typename tuple_help< N, std::tuple<> >::tuple_t;

      template< typename Input >
      static void apply( const Input& in, result_data< N >& data )
      {
         if( data.temp.size() != N ) {
            throw pegtl::parse_error( "column count mismatch", in );
         }
         tuple_t temp;
         tuple_init< N - 1 >::init( temp, data.temp );
         data.result.emplace_back( std::move( temp ) );
         data.temp.clear();
      }
   };

   // Another helper to print tuples of arbitrary sizes:

   inline void print_string( const std::string& s )
   {
      // Needs more elaborate escaping in practice...

      if( s.find( ',' ) != std::string::npos ) {
         std::cout << '"' << s << '"';
      }
      else {
         std::cout << s;
      }
   }

   template< unsigned I >
   struct print_help
   {
      template< typename... S >
      static void print( const std::tuple< S... >& t )
      {
         print_help< I - 1 >::print( t );
         std::cout << ',';
         print_string( std::get< I >( t ) );
      }
   };

   template<>
   struct print_help< 0 >
   {
      template< typename... S >
      static void print( const std::tuple< S... >& t )
      {
         print_string( std::get< 0 >( t ) );
      }
   };

   template< typename... S >
   void print_tuple( const std::tuple< S... >& t )
   {
      constexpr unsigned size = sizeof...( S );
      static_assert( size, "empty tuple doesn't work here" );
      print_help< size - 1 >::print( t );
      std::cout << std::endl;
   }

}  // csv2

int main( int argc, char** argv )
{
   for( int i = 1; i < argc; ++i ) {
      pegtl::file_input<> in( argv[ i ] );
      constexpr unsigned number_of_columns = 3;
      csv2::result_data< number_of_columns > data;
      pegtl::parse< pegtl::must< csv2::file< number_of_columns > >, csv2::action >( in, data );
      for( const auto& line : data.result ) {
         csv2::print_tuple( line );
      }
   }
   return 0;
}
