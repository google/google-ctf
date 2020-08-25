// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_REQUIRE_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_REQUIRE_HPP

#include "../config.hpp"

#include "skip_control.hpp"
#include "trivial.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< unsigned Amount >
         struct require;

         template<>
         struct require< 0 >
            : trivial< true >
         {
         };

         template< unsigned Amount >
         struct require
         {
            using analyze_t = analysis::generic< analysis::rule_type::OPT >;

            template< typename Input >
            static bool match( Input& in )
            {
               return in.size( Amount ) >= Amount;
            }
         };

         template< unsigned Amount >
         struct skip_control< require< Amount > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
