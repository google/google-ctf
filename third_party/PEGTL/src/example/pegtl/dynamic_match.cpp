// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <cstring>

#include <iostream>
#include <string>

#include <tao/pegtl.hpp>

namespace pegtl = tao::TAOCPP_PEGTL_NAMESPACE;

namespace dynamic
{
   struct long_literal_id
      : pegtl::plus< pegtl::not_one< '[' > >
   {
   };

   struct long_literal_open
      : pegtl::seq< pegtl::one< '[' >, long_literal_id, pegtl::one< '[' > >
   {
   };

   struct long_literal_mark
   {
      template< pegtl::apply_mode,
                pegtl::rewind_mode,
                template< typename... > class Action,
                template< typename... > class Control,
                typename Input >
      static bool match( Input& in, const std::string& id, const std::string& /*unused*/ )
      {
         if( in.size( id.size() ) >= id.size() ) {
            if( std::memcmp( in.current(), id.data(), id.size() ) == 0 ) {
               in.bump( id.size() );
               return true;
            }
         }
         return false;
      }
   };

   struct long_literal_close
      : pegtl::seq< pegtl::one< ']' >, long_literal_mark, pegtl::one< ']' > >
   {
   };

   struct long_literal_body
      : pegtl::any
   {
   };

   struct grammar
      : pegtl::if_must< long_literal_open, pegtl::until< long_literal_close, long_literal_body >, pegtl::eof >
   {
   };

   template< typename Rule >
   struct action
      : pegtl::nothing< Rule >
   {
   };

   template<>
   struct action< long_literal_id >
   {
      template< typename Input >
      static void apply( const Input& in, std::string& id, const std::string& /*unused*/ )
      {
         id = in.string();
      }
   };

   template<>
   struct action< long_literal_body >
   {
      template< typename Input >
      static void apply( const Input& in, const std::string& /*unused*/, std::string& body )
      {
         body += in.string();
      }
   };

}  // namespace dynamic

int main( int argc, char** argv )
{
   if( argc > 1 ) {
      std::string id;
      std::string body;

      pegtl::argv_input<> in( argv, 1 );
      pegtl::parse< dynamic::grammar, dynamic::action >( in, id, body );

      std::cout << "long literal id was: " << id << std::endl;
      std::cout << "long literal body was: " << body << std::endl;
   }
   return 0;
}
