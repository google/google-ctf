// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_HAS_APPLY_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_HAS_APPLY_HPP

#include <type_traits>

#include "../config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename, typename, typename... >
         struct has_apply : std::false_type
         {
         };

         template< typename A, typename... S >
         struct has_apply< A, decltype( A::apply( std::declval< S >()... ) ), S... > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
