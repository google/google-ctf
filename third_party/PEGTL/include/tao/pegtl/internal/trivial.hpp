// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_TRIVIAL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_TRIVIAL_HPP

#include "../config.hpp"

#include "skip_control.hpp"

#include "../analysis/counted.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< bool Result >
         struct trivial
         {
            using analyze_t = analysis::counted< analysis::rule_type::ANY, unsigned( !Result ) >;

            template< typename Input >
            static bool match( Input& ) noexcept
            {
               return Result;
            }
         };

         template< bool Result >
         struct skip_control< trivial< Result > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
