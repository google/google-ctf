// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_CONTRIB_COUNTER_HPP
#define TAOCPP_PEGTL_INCLUDE_CONTRIB_COUNTER_HPP

#include <cassert>
#include <utility>

#include "../config.hpp"
#include "../normal.hpp"

#include "../internal/demangle.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      struct counter_data
      {
         unsigned start = 0;
         unsigned success = 0;
         unsigned failure = 0;
      };

      struct counter_state
      {
         std::map< std::string, counter_data > counts;
      };

      template< typename Rule >
      struct counter
         : normal< Rule >
      {
         template< typename Input >
         static void start( const Input&, counter_state& ts )
         {
            ++ts.counts[ internal::demangle< Rule >() ].start;
         }

         template< typename Input >
         static void success( const Input&, counter_state& ts )
         {
            ++ts.counts[ internal::demangle< Rule >() ].success;
         }

         template< typename Input >
         static void failure( const Input&, counter_state& ts )
         {
            ++ts.counts[ internal::demangle< Rule >() ].failure;
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
