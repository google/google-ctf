// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_EOL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_EOL_HPP

#include "../config.hpp"

#include "skip_control.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct eol
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< typename Input >
            static bool match( Input& in )
            {
               using eol_t = typename Input::eol_t;
               return eol_t::match( in ).first;
            }
         };

         template<>
         struct skip_control< eol > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
