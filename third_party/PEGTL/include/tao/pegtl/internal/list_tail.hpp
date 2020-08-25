// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_LIST_TAIL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_LIST_TAIL_HPP

#include "../config.hpp"

#include "list.hpp"
#include "opt.hpp"
#include "seq.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Rule, typename Sep >
         using list_tail = seq< list< Rule, Sep >, opt< Sep > >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
