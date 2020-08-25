// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_PEEK_UTF16_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_PEEK_UTF16_HPP

#include <type_traits>

#include "../config.hpp"

#include "input_pair.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct peek_utf16
         {
            using data_t = char32_t;
            using pair_t = input_pair< char32_t >;

            using short_t = std::make_unsigned< char16_t >::type;

            static_assert( sizeof( short_t ) == 2, "expected size 2 for 16bit value" );
            static_assert( sizeof( char16_t ) == 2, "expected size 2 for 16bit value" );

            template< typename Input >
            static pair_t peek( Input& in )
            {
               const std::size_t s = in.size( 4 );
               if( s >= 2 ) {
                  const char32_t t = *reinterpret_cast< const short_t* >( in.current() );
                  if( ( t < 0xd800 ) || ( t > 0xdbff ) || ( s < 4 ) ) {
                     return { t, 2 };
                  }
                  const char32_t u = *reinterpret_cast< const short_t* >( in.current() + 2 );
                  if( ( u < 0xdc00 ) || ( u > 0xdfff ) ) {
                     return { t, 2 };
                  }
                  return { ( ( ( t & 0x03ff ) << 10 ) | ( u & 0x03ff ) ) + 0x10000, 4 };
               }
               return { 0, 0 };
            }
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
