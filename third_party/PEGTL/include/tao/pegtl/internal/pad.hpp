// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_PAD_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_PAD_HPP

#include "../config.hpp"

#include "seq.hpp"
#include "star.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Rule, typename Pad1, typename Pad2 = Pad1 >
         using pad = seq< star< Pad1 >, Rule, star< Pad2 > >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
