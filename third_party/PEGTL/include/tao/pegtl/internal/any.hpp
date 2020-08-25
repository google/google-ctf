// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_ANY_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_ANY_HPP

#include "../config.hpp"

#include "peek_char.hpp"
#include "skip_control.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Peek >
         struct any;

         template<>
         struct any< peek_char >
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< typename Input >
            static bool match( Input& in )
            {
               if( !in.empty() ) {
                  in.bump();
                  return true;
               }
               return false;
            }
         };

         template< typename Peek >
         struct any
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< typename Input >
            static bool match( Input& in )
            {
               if( !in.empty() ) {
                  if( const auto t = Peek::peek( in ) ) {
                     in.bump( t.size );
                     return true;
                  }
               }
               return false;
            }
         };

         template< typename Peek >
         struct skip_control< any< Peek > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
