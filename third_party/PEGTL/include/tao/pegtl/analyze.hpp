// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ANALYZE_HPP
#define TAOCPP_PEGTL_INCLUDE_ANALYZE_HPP

#include "config.hpp"

#include "analysis/analyze_cycles.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Rule >
      std::size_t analyze( const bool verbose = true )
      {
         return analysis::analyze_cycles< Rule >( verbose ).problems();
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
