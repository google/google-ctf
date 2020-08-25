// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <iomanip>
#include <iostream>

#define TAOCPP_PEGTL_PRETTY_DEMANGLE

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/counter.hpp>
#include <tao/pegtl/contrib/json.hpp>
#include <tao/pegtl/file_input.hpp>

using namespace tao::TAOCPP_PEGTL_NAMESPACE;
using grammar = must< json::text, eof >;

int main( int argc, char** argv )
{
   counter_state cs;

   for( int i = 1; i < argc; ++i ) {
      file_input<> in( argv[ i ] );
      parse< grammar, nothing, counter >( in, cs );
   }
   std::cout << std::right << std::setw( 72 ) << "RULE NAME" << std::left << "      START  SUCCESS  FAILURE" << std::endl;
   for( const auto& j : cs.counts ) {
      std::cout << std::right << std::setw( 72 ) << j.first << "   " << std::setw( 8 ) << j.second.start << " " << std::setw( 8 ) << j.second.success << " " << std::setw( 8 ) << j.second.failure << std::endl;
   }
   return 0;
}
