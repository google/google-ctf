// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_UTF16_HPP
#define TAOCPP_PEGTL_INCLUDE_UTF16_HPP

#include "config.hpp"

#include "internal/peek_utf16.hpp"
#include "internal/result_on_found.hpp"
#include "internal/rules.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace utf16
      {
         // clang-format off
         struct any : internal::any< internal::peek_utf16 > {};
         struct bom : internal::one< internal::result_on_found::SUCCESS, internal::peek_utf16, 0xfeff > {};
         template< char32_t... Cs > struct not_one : internal::one< internal::result_on_found::FAILURE, internal::peek_utf16, Cs... > {};
         template< char32_t Lo, char32_t Hi > struct not_range : internal::range< internal::result_on_found::FAILURE, internal::peek_utf16, Lo, Hi > {};
         template< char32_t... Cs > struct one : internal::one< internal::result_on_found::SUCCESS, internal::peek_utf16, Cs... > {};
         template< char32_t Lo, char32_t Hi > struct range : internal::range< internal::result_on_found::SUCCESS, internal::peek_utf16, Lo, Hi > {};
         template< char32_t... Cs > struct ranges : internal::ranges< internal::peek_utf16, Cs... > {};
         template< char32_t... Cs > struct string : internal::seq< internal::one< internal::result_on_found::SUCCESS, internal::peek_utf16, Cs >... > {};
         // clang-format on

      }  // namespace utf16

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
