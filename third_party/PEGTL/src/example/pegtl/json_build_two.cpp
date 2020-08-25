// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <vector>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/changes.hpp>
#include <tao/pegtl/contrib/json.hpp>

#include "json_classes.hpp"
#include "json_errors.hpp"
#include "json_unescape.hpp"

namespace examples
{
   // State class that stores the result of a JSON parsing run -- a single JSON object.
   // The other members are used temporarily, at the end of a (successful) parsing run
   // they are expected to be empty.

   struct json_state
   {
      std::shared_ptr< json_base > result;
      std::vector< std::string > keys;
      std::vector< std::shared_ptr< array_json > > arrays;
      std::vector< std::shared_ptr< object_json > > objects;
   };

   // Action and Control classes

   template< typename Rule >
   struct action : unescape_action< Rule >  // Inherit from json_unescape.hpp.
   {
   };

   template< typename Rule >
   struct control : errors< Rule >  // Inherit from json_errors.hpp.
   {
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::null >
   {
      static void apply0( json_state& state )
      {
         state.result = std::make_shared< null_json >();
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::true_ >
   {
      static void apply0( json_state& state )
      {
         state.result = std::make_shared< boolean_json >( true );
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::false_ >
   {
      static void apply0( json_state& state )
      {
         state.result = std::make_shared< boolean_json >( false );
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::number >
   {
      template< typename Input >
      static void apply( const Input& in, json_state& state )
      {
         state.result = std::make_shared< number_json >( std::stold( in.string() ) );  // NOTE: stold() is not quite correct for JSON but we'll use it for this simple example.
      }
   };

   // To parse a string, we change the state to decouple string parsing/unescaping

   struct string_state
      : public unescape_state_base
   {
      void success( json_state& state )
      {
         state.result = std::make_shared< string_json >( unescaped );
      }
   };

   template<>
   struct control< tao::TAOCPP_PEGTL_NAMESPACE::json::string::content >
      : tao::TAOCPP_PEGTL_NAMESPACE::change_state< tao::TAOCPP_PEGTL_NAMESPACE::json::string::content, string_state, errors >
   {
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::array::begin >
   {
      static void apply0( json_state& state )
      {
         state.arrays.push_back( std::make_shared< array_json >() );
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::array::element >
   {
      static void apply0( json_state& state )
      {
         state.arrays.back()->data.push_back( std::move( state.result ) );
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::array::end >
   {
      static void apply0( json_state& state )
      {
         state.result = std::move( state.arrays.back() );
         state.arrays.pop_back();
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::object::begin >
   {
      static void apply0( json_state& state )
      {
         state.objects.push_back( std::make_shared< object_json >() );
      }
   };

   // To parse a key, we change the state to decouple string parsing/unescaping

   struct key_state : unescape_state_base
   {
      void success( json_state& state )
      {
         state.keys.push_back( std::move( unescaped ) );
      }
   };

   template<>
   struct control< tao::TAOCPP_PEGTL_NAMESPACE::json::key::content >
      : tao::TAOCPP_PEGTL_NAMESPACE::change_state< tao::TAOCPP_PEGTL_NAMESPACE::json::key::content, key_state, errors >
   {
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::object::element >
   {
      static void apply0( json_state& state )
      {
         state.objects.back()->data[ std::move( state.keys.back() ) ] = std::move( state.result );
         state.keys.pop_back();
      }
   };

   template<>
   struct action< tao::TAOCPP_PEGTL_NAMESPACE::json::object::end >
   {
      static void apply0( json_state& state )
      {
         state.result = std::move( state.objects.back() );
         state.objects.pop_back();
      }
   };

   using grammar = tao::TAOCPP_PEGTL_NAMESPACE::must< tao::TAOCPP_PEGTL_NAMESPACE::json::text, tao::TAOCPP_PEGTL_NAMESPACE::eof >;

}  // namespace examples

int main( int argc, char** argv )
{
   if( argc != 2 ) {
      std::cerr << "usage: " << argv[ 0 ] << " <json>";
   }
   else {
      examples::json_state state;
      tao::TAOCPP_PEGTL_NAMESPACE::file_input<> in( argv[ 1 ] );
      tao::TAOCPP_PEGTL_NAMESPACE::parse< examples::grammar, examples::action, examples::control >( in, state );
      assert( state.keys.empty() );
      assert( state.arrays.empty() );
      assert( state.objects.empty() );
      std::cout << state.result << std::endl;
   }
   return 0;
}
