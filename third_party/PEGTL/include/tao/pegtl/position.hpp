// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_POSITION_HPP
#define TAOCPP_PEGTL_INCLUDE_POSITION_HPP

#include <cstdlib>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "config.hpp"

#include "internal/iterator.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      struct position
      {
         template< typename T >
         position( const internal::iterator& in_iter, T&& in_source )
            : byte( in_iter.byte ),
              line( in_iter.line ),
              byte_in_line( in_iter.byte_in_line ),
              source( std::forward< T >( in_source ) )
         {
         }

         std::size_t byte;
         std::size_t line;
         std::size_t byte_in_line;
         std::string source;
      };

      inline std::ostream& operator<<( std::ostream& o, const position& p )
      {
         return o << p.source << ':' << p.line << ':' << p.byte_in_line << '(' << p.byte << ')';
      }

      inline std::string to_string( const position& p )
      {
         std::ostringstream o;
         o << p;
         return o.str();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
