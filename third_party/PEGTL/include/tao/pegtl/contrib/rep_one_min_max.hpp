// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_CONTRIB_REP_ONE_MIN_MAX_HPP
#define TAOCPP_PEGTL_INCLUDE_CONTRIB_REP_ONE_MIN_MAX_HPP

#include <algorithm>

#include "../config.hpp"

#include "../analysis/counted.hpp"

#include "../internal/bump_help.hpp"
#include "../internal/skip_control.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< unsigned Min, unsigned Max, char C >
         struct rep_one_min_max
         {
            using analyze_t = analysis::counted< analysis::rule_type::ANY, Min >;

            static_assert( Min <= Max, "invalid rep_one_min_max rule (maximum number of repetitions smaller than minimum)" );

            template< typename Input >
            static bool match( Input& in )
            {
               const auto size = in.size( Max + 1 );
               if( size < Min ) {
                  return false;
               }
               std::size_t i = 0;
               while( ( i < size ) && ( in.peek_char( i ) == C ) ) {
                  ++i;
               }
               if( ( Min <= i ) && ( i <= Max ) ) {
                  bump_help< result_on_found::SUCCESS, Input, char, C >( in, i );
                  return true;
               }
               return false;
            }
         };

         template< unsigned Min, unsigned Max, char C >
         struct skip_control< rep_one_min_max< Min, Max, C > > : std::true_type
         {
         };

      }  // namespace internal

      inline namespace ascii
      {
         template< unsigned Min, unsigned Max, char C >
         struct rep_one_min_max : internal::rep_one_min_max< Min, Max, C >
         {
         };

         struct ellipsis : internal::rep_one_min_max< 3, 3, '.' >
         {
         };

      }  // namespace ascii

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
