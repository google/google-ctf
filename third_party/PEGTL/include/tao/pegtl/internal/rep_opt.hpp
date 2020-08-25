// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_OPT_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_REP_OPT_HPP

#include "../config.hpp"

#include "duseltronik.hpp"
#include "seq.hpp"
#include "skip_control.hpp"

#include "../apply_mode.hpp"
#include "../rewind_mode.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< unsigned Max, typename... Rules >
         struct rep_opt
         {
            using analyze_t = analysis::generic< analysis::rule_type::OPT, Rules... >;

            template< apply_mode A,
                      rewind_mode,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               for( unsigned i = 0; ( i != Max ) && duseltronik< seq< Rules... >, A, rewind_mode::REQUIRED, Action, Control >::match( in, st... ); ++i ) {
               }
               return true;
            }
         };

         template< unsigned Max, typename... Rules >
         struct skip_control< rep_opt< Max, Rules... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
