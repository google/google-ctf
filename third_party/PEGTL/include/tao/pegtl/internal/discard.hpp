// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_DISCARD_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_DISCARD_HPP

#include "../config.hpp"

#include "skip_control.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct discard
         {
            using analyze_t = analysis::generic< analysis::rule_type::OPT >;

            template< typename Input >
            static bool match( Input& in )
            {
               in.discard();
               return true;
            }
         };

         template<>
         struct skip_control< discard > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
