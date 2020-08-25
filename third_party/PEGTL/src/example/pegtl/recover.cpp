// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

// This is a small experiment with a grammar that can recover from errors.
//
// Triggered by https://github.com/taocpp/PEGTL/issues/55
//
// The grammar will recognise simple expressions terminated by semicolons.
// When an expression fails to parse, it skips to the next expression
// by looking for the terminator.
//
// Try: build/src/example/pegtl/recover '1+2*3;1+2*(3-)-4;-5;6/;7*(8+9)'

#include <iostream>
#include <string>

#include <tao/pegtl.hpp>

using namespace tao::TAOCPP_PEGTL_NAMESPACE;

// clang-format off

template< typename T >
struct skipping : until< T > {};

template< typename R, typename T >
struct recoverable : sor< try_catch< must< R >, T >, skipping< T > > {};

struct expr_sum;
struct expr_identifier : identifier {};
struct expr_number : plus< digit > {};
struct expr_braced : if_must< one< '(' >, pad< expr_sum, space >, one< ')' > > {};

struct expr_value : sor< expr_identifier, expr_number, expr_braced > {};

struct expr_power : list< must< expr_value >, one< '^' >, space > {};
struct expr_prod : list_must< expr_power, one< '*', '/', '%' >, space > {};
struct expr_sum : list_must< expr_prod, one< '+', '-' >, space > {};

struct term : sor< one< ';' >, eof > {};
struct expr : pad< expr_sum, space > {};
struct recoverable_expr : recoverable< expr, term > {};

struct my_grammar : star< not_at< eof >, recoverable_expr > {};

// clang-format on

template< typename Rule >
struct my_action
   : nothing< Rule >
{
};

template< typename T >
struct my_action< skipping< T > >
{
   template< typename Input >
   static void apply( const Input& in, bool& error )
   {
      if( !error ) {
         std::cout << in.position() << ": Invalid expression \"" << in.string() << "\"" << std::endl;
      }
      error = true;
   }
};

template< typename R >
struct found
{
   template< typename Input >
   static void apply( const Input& in, bool& error )
   {
      if( !error ) {
         std::cout << in.position() << ": Found " << internal::demangle< R >() << ": \"" << in.string() << "\"" << std::endl;
      }
   }
};

// clang-format off
// template<> struct my_action< expr_identifier > : found< expr_identifier > {};
// template<> struct my_action< expr_number > : found< expr_number > {};
// template<> struct my_action< expr_braced > : found< expr_braced > {};
// template<> struct my_action< expr_value > : found< expr_value > {};
// template<> struct my_action< expr_power > : found< expr_power > {};
// template<> struct my_action< expr_prod > : found< expr_prod > {};
// template<> struct my_action< expr_sum > : found< expr_sum > {};
template<> struct my_action< expr > : found< expr > {};
// clang-format on

template<>
struct my_action< recoverable_expr >
{
   template< typename Input >
   static void apply( const Input& /*unused*/, bool& error )
   {
      error = false;
      std::cout << std::string( 79, '-' ) << std::endl;
   }
};

template< typename Rule >
struct my_control
   : normal< Rule >
{
   template< typename Input, typename... States >
   static void raise( const Input& in, States&&... /*unused*/ )
   {
      std::cout << in.position() << ": Parse error matching " << internal::demangle< Rule >() << std::endl;
      throw parse_error( "parse error matching " + internal::demangle< Rule >(), in );
   }
};

int main( int argc, char** argv )
{
   for( int i = 1; i < argc; ++i ) {
      argv_input<> in( argv, i );
      bool error = false;
      parse< my_grammar, my_action, my_control >( in, error );
   }
   return 0;
}
