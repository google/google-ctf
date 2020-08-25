// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_TAOCPP_PEGTL_STRING_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_TAOCPP_PEGTL_STRING_HPP

#include <cstddef>
#include <type_traits>

#include "../ascii.hpp"
#include "../config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      // Inspired by https://github.com/irrequietus/typestring
      // Rewritten and reduced to what is needed for the PEGTL
      // and to work with Visual Studio 2015.

      namespace internal
      {
         template< typename, typename, typename, typename, typename, typename, typename, typename >
         struct string_join;

         template< template< char... > class S, char... C0s, char... C1s, char... C2s, char... C3s, char... C4s, char... C5s, char... C6s, char... C7s >
         struct string_join< S< C0s... >, S< C1s... >, S< C2s... >, S< C3s... >, S< C4s... >, S< C5s... >, S< C6s... >, S< C7s... > >
         {
            using type = S< C0s..., C1s..., C2s..., C3s..., C4s..., C5s..., C6s..., C7s... >;
         };

         template< template< char... > class S, char, bool >
         struct string_at
         {
            using type = S<>;
         };

         template< template< char... > class S, char C >
         struct string_at< S, C, true >
         {
            using type = S< C >;
         };

         template< typename T, std::size_t S >
         struct string_max_length
         {
            static_assert( S <= 512, "String longer than 512 (excluding terminating \\0)!" );
            using type = T;
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#define TAOCPP_PEGTL_INTERNAL_EMPTY()
#define TAOCPP_PEGTL_INTERNAL_DEFER( X ) X TAOCPP_PEGTL_INTERNAL_EMPTY()
#define TAOCPP_PEGTL_INTERNAL_EXPAND( ... ) __VA_ARGS__

#define TAOCPP_PEGTL_INTERNAL_STRING_AT( S, x, n ) \
   tao::TAOCPP_PEGTL_NAMESPACE::internal::string_at< S, ( 0##n < sizeof( x ) ) ? x[ 0##n ] : 0, ( 0##n < sizeof( x ) - 1 ) >::type

#define TAOCPP_PEGTL_INTERNAL_JOIN_8( M, S, x, n )                                                     \
   tao::TAOCPP_PEGTL_NAMESPACE::internal::string_join< TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##0 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##1 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##2 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##3 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##4 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##5 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##6 ), \
                                                       TAOCPP_PEGTL_INTERNAL_DEFER( M )( S, x, n##7 ) >::type

#define TAOCPP_PEGTL_INTERNAL_STRING_8( S, x, n ) \
   TAOCPP_PEGTL_INTERNAL_JOIN_8( TAOCPP_PEGTL_INTERNAL_STRING_AT, S, x, n )

#define TAOCPP_PEGTL_INTERNAL_STRING_64( S, x, n ) \
   TAOCPP_PEGTL_INTERNAL_JOIN_8( TAOCPP_PEGTL_INTERNAL_STRING_8, S, x, n )

#define TAOCPP_PEGTL_INTERNAL_STRING_512( S, x, n ) \
   TAOCPP_PEGTL_INTERNAL_JOIN_8( TAOCPP_PEGTL_INTERNAL_STRING_64, S, x, n )

#define TAOCPP_PEGTL_INTERNAL_STRING( S, x ) \
   TAOCPP_PEGTL_INTERNAL_EXPAND(             \
      TAOCPP_PEGTL_INTERNAL_EXPAND(          \
         TAOCPP_PEGTL_INTERNAL_EXPAND(       \
            tao::TAOCPP_PEGTL_NAMESPACE::internal::string_max_length< TAOCPP_PEGTL_INTERNAL_STRING_512( S, x, ), sizeof( x ) - 1 >::type ) ) )

#define TAOCPP_PEGTL_STRING( x ) \
   TAOCPP_PEGTL_INTERNAL_STRING( tao::TAOCPP_PEGTL_NAMESPACE::ascii::string, x )

#define TAOCPP_PEGTL_ISTRING( x ) \
   TAOCPP_PEGTL_INTERNAL_STRING( tao::TAOCPP_PEGTL_NAMESPACE::ascii::istring, x )

#define TAOCPP_PEGTL_KEYWORD( x ) \
   TAOCPP_PEGTL_INTERNAL_STRING( tao::TAOCPP_PEGTL_NAMESPACE::ascii::keyword, x )

#endif
