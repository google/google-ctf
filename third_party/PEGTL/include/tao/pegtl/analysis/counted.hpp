// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ANALYSIS_COUNTED_HPP
#define TAOCPP_PEGTL_INCLUDE_ANALYSIS_COUNTED_HPP

#include "../config.hpp"

#include "generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace analysis
      {
         template< rule_type Type, unsigned Count, typename... Rules >
         struct counted
            : generic< ( Count != 0 ) ? Type : rule_type::OPT, Rules... >
         {
         };

      }  // namespace analysis

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
