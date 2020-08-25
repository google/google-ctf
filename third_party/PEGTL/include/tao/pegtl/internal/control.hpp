// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_CONTROL_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_CONTROL_HPP

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
         template< template< typename... > class Control, typename... Rules >
         struct control
         {
            using analyze_t = analysis::generic< analysis::rule_type::SEQ, Rules... >;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               return duseltronik< seq< Rules... >, A, M, Action, Control >::match( in, st... );
            }
         };

         template< template< typename... > class Control, typename... Rules >
         struct skip_control< control< Control, Rules... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
