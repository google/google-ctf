// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_DEMANGLE_SANITISE_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_DEMANGLE_SANITISE_HPP

#include <string>

#include "../config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         inline void demangle_sanitise_chars( std::string& s )
         {
            std::string::size_type p;
            while( ( p = s.find( "(char)" ) ) != std::string::npos ) {
               int c = 0;
               std::string::size_type q;
               for( q = p + 6; ( q < s.size() ) && ( s[ q ] >= '0' ) && ( s[ q ] <= '9' ); ++q ) {
                  c *= 10;
                  c += s[ q ] - '0';
               }
               if( c == '\'' ) {
                  s.replace( p, q - p, "'\\''" );
               }
               else if( c == '\\' ) {
                  s.replace( p, q - p, "'\\\\'" );
               }
               else if( ( c < 32 ) || ( c > 126 ) ) {
                  s.replace( p, 6, std::string() );
               }
               else {
                  s.replace( p, q - p, std::string( 1, '\'' ) + char( c ) + '\'' );
               }
            }
         }

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
