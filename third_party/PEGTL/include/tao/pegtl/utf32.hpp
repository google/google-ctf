// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_UTF32_HPP
#define TAOCPP_PEGTL_INCLUDE_UTF32_HPP

#include "config.hpp"

#include "internal/peek_utf32.hpp"
#include "internal/result_on_found.hpp"
#include "internal/rules.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace utf32
      {
         // clang-format off
         struct any : internal::any< internal::peek_utf32 > {};
         struct bom : internal::one< internal::result_on_found::SUCCESS, internal::peek_utf32, 0xfeff > {};
         template< char32_t... Cs > struct not_one : internal::one< internal::result_on_found::FAILURE, internal::peek_utf32, Cs... > {};
         template< char32_t Lo, char32_t Hi > struct not_range : internal::range< internal::result_on_found::FAILURE, internal::peek_utf32, Lo, Hi > {};
         template< char32_t... Cs > struct one : internal::one< internal::result_on_found::SUCCESS, internal::peek_utf32, Cs... > {};
         template< char32_t Lo, char32_t Hi > struct range : internal::range< internal::result_on_found::SUCCESS, internal::peek_utf32, Lo, Hi > {};
         template< char32_t... Cs > struct ranges : internal::ranges< internal::peek_utf32, Cs... > {};
         template< char32_t... Cs > struct string : internal::seq< internal::one< internal::result_on_found::SUCCESS, internal::peek_utf32, Cs >... > {};
         // clang-format on

      }  // namespace utf32

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
