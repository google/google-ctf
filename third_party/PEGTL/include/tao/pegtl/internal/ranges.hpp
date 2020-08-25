// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_RANGES_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_RANGES_HPP

#include "../config.hpp"

#include "bump_help.hpp"
#include "range.hpp"
#include "skip_control.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< int Eol, typename Char, Char... Cs >
         struct ranges_impl;

         template< int Eol, typename Char >
         struct ranges_impl< Eol, Char >
         {
            static constexpr bool can_match_eol = false;

            static bool match( const Char ) noexcept
            {
               return false;
            }
         };

         template< int Eol, typename Char, Char Eq >
         struct ranges_impl< Eol, Char, Eq >
         {
            static constexpr bool can_match_eol = ( Eq == Eol );

            static bool match( const Char c ) noexcept
            {
               return c == Eq;
            }
         };

         template< int Eol, typename Char, Char Lo, Char Hi, Char... Cs >
         struct ranges_impl< Eol, Char, Lo, Hi, Cs... >
         {
            static constexpr bool can_match_eol = ( ( ( Lo <= Eol ) && ( Eol <= Hi ) ) || ranges_impl< Eol, Char, Cs... >::can_match_eol );

            static bool match( const Char c ) noexcept
            {
               return ( ( Lo <= c ) && ( c <= Hi ) ) || ranges_impl< Eol, Char, Cs... >::match( c );
            }
         };

         template< typename Peek, typename Peek::data_t... Cs >
         struct ranges
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< int Eol >
            struct can_match_eol
            {
               static constexpr bool value = ranges_impl< Eol, typename Peek::data_t, Cs... >::can_match_eol;
            };

            template< typename Input >
            static bool match( Input& in )
            {
               using eol_t = typename Input::eol_t;

               if( !in.empty() ) {
                  if( const auto t = Peek::peek( in ) ) {
                     if( ranges_impl< eol_t::ch, typename Peek::data_t, Cs... >::match( t.data ) ) {
                        bump_impl< can_match_eol< eol_t::ch >::value >::bump( in, t.size );
                        return true;
                     }
                  }
               }
               return false;
            }
         };

         template< typename Peek, typename Peek::data_t Lo, typename Peek::data_t Hi >
         struct ranges< Peek, Lo, Hi >
            : range< result_on_found::SUCCESS, Peek, Lo, Hi >
         {
         };

         template< typename Peek, typename Peek::data_t... Cs >
         struct skip_control< ranges< Peek, Cs... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
