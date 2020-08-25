// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_APPLY_MODE_HPP
#define TAOCPP_PEGTL_INCLUDE_APPLY_MODE_HPP

#include "config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      enum class apply_mode : bool
      {
         ACTION = true,
         NOTHING = false
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
