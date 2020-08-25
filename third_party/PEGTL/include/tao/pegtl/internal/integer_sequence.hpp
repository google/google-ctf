// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_INTEGER_SEQUENCE_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_INTEGER_SEQUENCE_HPP

#include <cstddef>
#include <type_traits>
#include <utility>

#include "../config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename T, T... Ns >
         struct integer_sequence
         {
            using value_type = T;

            static constexpr std::size_t size() noexcept
            {
               return sizeof...( Ns );
            }
         };

         template< std::size_t... Ns >
         using index_sequence = integer_sequence< std::size_t, Ns... >;

         template< bool V, bool E >
         struct generate_sequence;

         template<>
         struct generate_sequence< false, true >
         {
            template< typename T, T M, T N, std::size_t S, T... Ns >
            using f = integer_sequence< T, Ns... >;
         };

         template<>
         struct generate_sequence< true, true >
         {
            template< typename T, T M, T N, std::size_t S, T... Ns >
            using f = integer_sequence< T, Ns..., S >;
         };

         template<>
         struct generate_sequence< false, false >
         {
            template< typename T, T M, T N, std::size_t S, T... Ns >
            using f = typename generate_sequence< ( N & ( M / 2 ) ) != 0, ( M / 2 ) == 0 >::template f< T, M / 2, N, 2 * S, Ns..., ( Ns + S )... >;
         };

         template<>
         struct generate_sequence< true, false >
         {
            template< typename T, T M, T N, std::size_t S, T... Ns >
            using f = typename generate_sequence< ( N & ( M / 2 ) ) != 0, ( M / 2 ) == 0 >::template f< T, M / 2, N, 2 * S + 1, Ns..., ( Ns + S )..., 2 * S >;
         };

         template< typename T, T N >
         struct memoize_sequence
         {
            static_assert( N < T( 1 << 20 ), "N too large" );
            using type = typename generate_sequence< false, false >::template f< T, ( N < T( 1 << 1 ) ) ? T( 1 << 1 ) : ( N < T( 1 << 2 ) ) ? T( 1 << 2 ) : ( N < T( 1 << 3 ) ) ? T( 1 << 3 ) : ( N < T( 1 << 4 ) ) ? T( 1 << 4 ) : ( N < T( 1 << 5 ) ) ? T( 1 << 5 ) : ( N < T( 1 << 6 ) ) ? T( 1 << 6 ) : ( N < T( 1 << 7 ) ) ? T( 1 << 7 ) : ( N < T( 1 << 8 ) ) ? T( 1 << 8 ) : ( N < T( 1 << 9 ) ) ? T( 1 << 9 ) : ( N < T( 1 << 10 ) ) ? T( 1 << 10 ) : T( 1 << 20 ), N, 0 >;
         };

         template< typename T, T N >
         using make_integer_sequence = typename memoize_sequence< T, N >::type;

         template< std::size_t N >
         using make_index_sequence = make_integer_sequence< std::size_t, N >;

         template< typename... Ts >
         using index_sequence_for = make_index_sequence< sizeof...( Ts ) >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
