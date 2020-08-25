// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_SKIP_CONTROL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_SKIP_CONTROL_HPP

#include <type_traits>

#include "../config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         // This class is a simple tagging mechanism.
         // By default, skip_control< Rule >::value
         // is 'false'. Each internal (!) rule that should
         // be hidden from the control and action class'
         // callbacks simply specializes skip_control<>
         // to return 'true' for the above expression.

         template< typename Rule >
         struct skip_control : std::false_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
