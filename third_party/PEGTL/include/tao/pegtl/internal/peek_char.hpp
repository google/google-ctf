// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_PEEK_CHAR_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_PEEK_CHAR_HPP

#include <cstddef>

#include "../config.hpp"

#include "input_pair.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct peek_char
         {
            using data_t = char;
            using pair_t = input_pair< char >;

            template< typename Input >
            static pair_t peek( Input& in, const std::size_t o = 0 )
            {
               return { in.peek_char( o ), 1 };
            }
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
