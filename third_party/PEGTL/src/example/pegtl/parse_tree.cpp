// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <iostream>
#include <string>
#include <type_traits>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/parse_tree.hpp>
#include <tao/pegtl/internal/demangle.hpp>

using namespace tao::TAOCPP_PEGTL_NAMESPACE;

namespace example
{
   // clang-format off

   // the grammar
   struct integer : plus< digit > {};
   struct variable : identifier {};

   struct plus : pad< one< '+' >, space > {};
   struct minus : pad< one< '-' >, space > {};
   struct multiply : pad< one< '*' >, space > {};
   struct divide : pad< one< '/' >, space > {};

   struct open_bracket : seq< one< '(' >, star< space > > {};
   struct close_bracket : seq< star< space >, one< ')' > > {};

   struct expression;
   struct bracketed : if_must< open_bracket, expression, close_bracket > {};
   struct value : sor< integer, variable, bracketed >{};
   struct product : list_must< value, sor< multiply, divide > > {};
   struct expression : list_must< product, sor< plus, minus > > {};

   struct grammar : must< expression, eof > {};

   // select which rules in the grammar will produce parse tree nodes:
   template< typename > struct store_simple : std::false_type {};
   template< typename > struct store_content : std::false_type {};

   template<> struct store_content< integer > : std::true_type {};
   template<> struct store_content< variable > : std::true_type {};

   template<> struct store_simple< plus > : std::true_type {};
   template<> struct store_simple< minus > : std::true_type {};
   template<> struct store_simple< multiply > : std::true_type {};
   template<> struct store_simple< divide > : std::true_type {};

   template<> struct store_simple< product > : std::true_type {};
   template<> struct store_simple< expression > : std::true_type {};

   // clang-format on

   // use actions to transform the parse tree:
   template< typename Rule >
   struct action
      : nothing< Rule >
   {
   };

   template<>
   struct action< product >
   {
      // recursively rearrange nodes. the basic principle is:
      //
      // from:          PROD/EXPR
      //                /   |   \          (LHS... may be one or more children, followed by:)
      //             LHS... OP   RHS       (OP is one operator, RHS is a single child)
      //
      // to:               OP
      //                  /  \             (OP now has two children, the original PROD/EXPR and RHS)
      //         PROD/EXPR    RHS          (Note that PROD/EXPR has two fewer children now)
      //             |
      //            LHS...
      //
      // if only one child is left for LHS..., replace the PROD/EXPR with the child directly.
      // otherwise, perform the above transformation, than apply it recursively until LHS...
      // becomes a single child, which than repaces the parent node and the recursion ends.
      static void rearrange( std::unique_ptr< parse_tree::node >& n )
      {
         auto& c = n->children;
         if( c.size() == 1 ) {
            n = std::move( c.back() );
         }
         else {
            auto r = std::move( c.back() );
            c.pop_back();
            auto o = std::move( c.back() );
            c.pop_back();
            o->children.emplace_back( std::move( n ) );
            o->children.emplace_back( std::move( r ) );
            n = std::move( o );
            rearrange( n->children.front() );
         }
      }

      template< typename Input >
      static void apply( const Input& /*unused*/, parse_tree::state& s )
      {
         rearrange( s.back()->children.back() );
      }
   };

   template<>
   struct action< expression >
      : action< product >
   {
   };

   void print_node( const parse_tree::node& n, const std::string& s = "" )
   {
      if( n.id != nullptr ) {
         if( n.end.data != nullptr ) {
            std::cout << s << internal::demangle( n.id->name() ) << " \"" << std::string( n.begin.data, n.end.data ) << "\" at " << position( n.begin, "" ) << " to " << position( n.end, "" ) << std::endl;
         }
         else {
            std::cout << s << internal::demangle( n.id->name() ) << " at " << position( n.begin, "" ) << std::endl;
         }
      }
      else {
         std::cout << "ROOT" << std::endl;
      }
      if( !n.children.empty() ) {
         const auto s2 = s + "  ";
         for( auto& up : n.children ) {
            print_node( *up, s2 );
         }
      }
   }

}  // namespace example

int main( int argc, char** argv )
{
   for( int i = 1; i < argc; ++i ) {
      argv_input<> in( argv, i );

      parse_tree::state s;
      parse< example::grammar, example::action, parse_tree::make_builder< example::store_simple, example::store_content >::type >( in, s );
      example::print_node( s.root() );
   }
   return 0;
}
