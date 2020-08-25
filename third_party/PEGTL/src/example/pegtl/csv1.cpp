// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <tao/pegtl.hpp>

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace csv1
{
   // Simple CSV-file format for an unknown-at-compile-time number of values per
   // line, the values are space/tab-padded integers, comment lines start with
   // a hash and are ignored; neither the grammar nor the included actions make
   // sure that the number of values per line is always the same; last line can
   // end with an LF or CR+LF but doesn't have to.

   // Example file contents parsed by this grammar (excluding C++ comment intro):
   // # This is a comment
   // 123 , 124,41,1
   //  1,2,3,4
   // 1
   //    1,2

   // clang-format off
   struct value : pegtl::plus< pegtl::digit > {};
   struct value_item : pegtl::pad< value, pegtl::blank > {};
   struct value_list : pegtl::list_must< value_item, pegtl::one< ',' > > {};
   struct value_line : pegtl::if_must< value_list, pegtl::eolf > {};
   struct comment_line : pegtl::seq< pegtl::one< '#' >, pegtl::until< pegtl::eolf > > {};
   struct line : pegtl::sor< comment_line, value_line > {};
   struct file : pegtl::until< pegtl::eof, line > {};
   // clang-format on

   // Data structure to store the result of a parsing run:

   using result_data = std::vector< std::vector< unsigned long > >;

   // Action and control classes to fill in the above data structure:

   template< typename Rule >
   struct action
      : pegtl::nothing< Rule >
   {
   };

   template<>
   struct action< value >
   {
      template< typename Input >
      static void apply( const Input& in, result_data& data )
      {
         assert( !data.empty() );
         data.back().push_back( std::stoul( in.string() ) );
      }
   };

   template< typename Rule >
   struct control
      : pegtl::normal< Rule >
   {
   };

   template<>
   struct control< value_line >
      : pegtl::normal< value_line >
   {
      template< typename Input >
      static void start( Input& /*unused*/, result_data& data )
      {
         data.emplace_back();
      }

      template< typename Input >
      static void failure( Input& /*unused*/, result_data& data )
      {
         assert( !data.empty() );
         data.pop_back();
      }
   };

}  // csv1

int main( int argc, char** argv )
{
   for( int i = 1; i < argc; ++i ) {
      pegtl::file_input<> in( argv[ i ] );
      csv1::result_data data;
      pegtl::parse< pegtl::must< csv1::file >, csv1::action, csv1::control >( in, data );
      for( const auto& line : data ) {
         assert( !line.empty() );  // The grammar doesn't allow empty lines.
         std::cout << line.front();
         for( std::size_t j = 1; j < line.size(); ++j ) {
            std::cout << ", " << line[ j ];
         }
         std::cout << std::endl;
      }
   }
   return 0;
}
