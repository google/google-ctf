// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_IDENTIFIER_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_IDENTIFIER_HPP

#include "../config.hpp"

#include "peek_char.hpp"
#include "ranges.hpp"
#include "seq.hpp"
#include "star.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         using identifier_first = ranges< peek_char, 'a', 'z', 'A', 'Z', '_' >;
         using identifier_other = ranges< peek_char, 'a', 'z', 'A', 'Z', '0', '9', '_' >;
         using identifier = seq< identifier_first, star< identifier_other > >;

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
