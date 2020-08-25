// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_STAR_MUST_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_STAR_MUST_HPP

#include "../config.hpp"

#include "if_must.hpp"
#include "star.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Cond, typename... Rules >
         using star_must = star< if_must< Cond, Rules... > >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
