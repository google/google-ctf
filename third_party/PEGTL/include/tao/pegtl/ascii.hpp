// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ASCII_HPP
#define TAOCPP_PEGTL_INCLUDE_ASCII_HPP

#include "config.hpp"
#include "eol.hpp"

#include "internal/result_on_found.hpp"
#include "internal/rules.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      inline namespace ascii
      {
         // clang-format off
         struct alnum : internal::alnum {};
         struct alpha : internal::alpha {};
         struct any : internal::any< internal::peek_char > {};
         struct blank : internal::one< internal::result_on_found::SUCCESS, internal::peek_char, ' ', '\t' > {};
         struct digit : internal::range< internal::result_on_found::SUCCESS, internal::peek_char, '0', '9' > {};
         struct eolf : internal::eolf {};
         struct identifier_first : internal::identifier_first {};
         struct identifier_other : internal::identifier_other {};
         struct identifier : internal::identifier {};
         template< char... Cs > struct istring : internal::istring< Cs... > {};
         template< char... Cs > struct keyword : internal::seq< internal::string< Cs... >, internal::not_at< internal::identifier_other > > {};
         struct lower : internal::range< internal::result_on_found::SUCCESS, internal::peek_char, 'a', 'z' > {};
         template< char... Cs > struct not_one : internal::one< internal::result_on_found::FAILURE, internal::peek_char, Cs... > {};
         template< char Lo, char Hi > struct not_range : internal::range< internal::result_on_found::FAILURE, internal::peek_char, Lo, Hi > {};
         struct nul : internal::one< internal::result_on_found::SUCCESS, internal::peek_char, char( 0 ) > {};
         template< char... Cs > struct one : internal::one< internal::result_on_found::SUCCESS, internal::peek_char, Cs... > {};
         struct print : internal::range< internal::result_on_found::SUCCESS, internal::peek_char, char( 32 ), char( 126 ) > {};
         template< char Lo, char Hi > struct range : internal::range< internal::result_on_found::SUCCESS, internal::peek_char, Lo, Hi > {};
         template< char... Cs > struct ranges : internal::ranges< internal::peek_char, Cs... > {};
         struct seven : internal::range< internal::result_on_found::SUCCESS, internal::peek_char, char( 0 ), char( 127 ) > {};
         struct shebang : internal::if_must< internal::string< '#', '!' >, internal::until< internal::eolf > > {};
         struct space : internal::one< internal::result_on_found::SUCCESS, internal::peek_char, ' ', '\n', '\r', '\t', '\v', '\f' > {};
         template< char... Cs > struct string : internal::string< Cs... > {};
         template< char C > struct two : internal::string< C, C > {};
         struct upper : internal::range< internal::result_on_found::SUCCESS, internal::peek_char, 'A', 'Z' > {};
         struct xdigit : internal::ranges< internal::peek_char, '0', '9', 'a', 'f', 'A', 'F' > {};
         // clang-format on

         template<>
         struct keyword<>
         {
            template< typename Input >
            static bool match( Input& ) noexcept
            {
               static_assert( sizeof( Input ) == 0, "empty keywords not allowed" );
               return false;
            }
         };

      }  // namespace ascii

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "internal/pegtl_string.hpp"

#endif
