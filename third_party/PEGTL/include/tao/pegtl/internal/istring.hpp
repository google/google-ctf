// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_ISTRING_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_ISTRING_HPP

#include <type_traits>

#include "../config.hpp"

#include "bump_help.hpp"
#include "result_on_found.hpp"
#include "skip_control.hpp"
#include "trivial.hpp"

#include "../analysis/counted.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< char C >
         using is_alpha = std::integral_constant< bool, ( ( 'a' <= C ) && ( C <= 'z' ) ) || ( ( 'A' <= C ) && ( C <= 'Z' ) ) >;

         template< char C, bool A = is_alpha< C >::value >
         struct ichar_equal;

         template< char C >
         struct ichar_equal< C, true >
         {
            static bool match( const char c ) noexcept
            {
               return ( C | 0x20 ) == ( c | 0x20 );
            }
         };

         template< char C >
         struct ichar_equal< C, false >
         {
            static bool match( const char c ) noexcept
            {
               return c == C;
            }
         };

         template< char... Cs >
         struct istring_equal;

         template<>
         struct istring_equal<>
         {
            static bool match( const char* ) noexcept
            {
               return true;
            }
         };

         template< char C, char... Cs >
         struct istring_equal< C, Cs... >
         {
            static bool match( const char* r ) noexcept
            {
               return ichar_equal< C >::match( *r ) && istring_equal< Cs... >::match( r + 1 );
            }
         };

         template< char... Cs >
         struct istring;

         template<>
         struct istring<>
            : trivial< true >
         {
         };

         template< char... Cs >
         struct istring
         {
            using analyze_t = analysis::counted< analysis::rule_type::ANY, sizeof...( Cs ) >;

            template< typename Input >
            static bool match( Input& in )
            {
               if( in.size( sizeof...( Cs ) ) >= sizeof...( Cs ) ) {
                  if( istring_equal< Cs... >::match( in.current() ) ) {
                     bump_help< result_on_found::SUCCESS, Input, char, Cs... >( in, sizeof...( Cs ) );
                     return true;
                  }
               }
               return false;
            }
         };

         template< char... Cs >
         struct skip_control< istring< Cs... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
