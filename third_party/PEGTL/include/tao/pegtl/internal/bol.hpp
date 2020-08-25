// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_BOL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_BOL_HPP

#include "../config.hpp"

#include "skip_control.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct bol
         {
            using analyze_t = analysis::generic< analysis::rule_type::OPT >;

            template< typename Input >
            static bool match( Input& in ) noexcept
            {
               return in.byte_in_line() == 0;
            }
         };

         template<>
         struct skip_control< bol > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
