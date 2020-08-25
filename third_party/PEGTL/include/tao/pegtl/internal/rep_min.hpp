// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_MIN_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_MIN_HPP

#include "../config.hpp"

#include "rep.hpp"
#include "seq.hpp"
#include "star.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< unsigned Min, typename Rule, typename... Rules >
         using rep_min = seq< rep< Min, Rule, Rules... >, star< Rule, Rules... > >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
