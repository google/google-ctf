// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_LIST_TAIL_PAD_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_LIST_TAIL_PAD_HPP

#include "../config.hpp"

#include "list.hpp"
#include "opt.hpp"
#include "pad.hpp"
#include "seq.hpp"
#include "star.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Rule, typename Sep, typename Pad >
         using list_tail_pad = seq< list< Rule, pad< Sep, Pad > >, opt< star< Pad >, Sep > >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
