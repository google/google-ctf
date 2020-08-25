// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_BUMP_UTIL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_BUMP_UTIL_HPP

#include <cstddef>
#include <type_traits>

#include "../config.hpp"

#include "result_on_found.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< bool >
         struct bump_impl;

         template<>
         struct bump_impl< true >
         {
            template< typename Input >
            static void bump( Input& in, const std::size_t count ) noexcept
            {
               in.bump( count );
            }
         };

         template<>
         struct bump_impl< false >
         {
            template< typename Input >
            static void bump( Input& in, const std::size_t count ) noexcept
            {
               in.bump_in_this_line( count );
            }
         };

         template< bool... >
         struct bool_list
         {
         };

         template< bool... Bs >
         using bool_and = std::is_same< bool_list< Bs..., true >, bool_list< true, Bs... > >;

         template< result_on_found R, typename Input, typename Char, Char... Cs >
         void bump_help( Input& in, const std::size_t count ) noexcept
         {
            using eol_t = typename Input::eol_t;
            bump_impl< bool_and< ( Cs != eol_t::ch )... >::value != bool( R ) >::bump( in, count );
         }

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
