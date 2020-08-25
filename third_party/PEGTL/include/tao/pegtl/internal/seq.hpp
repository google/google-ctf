// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_SEQ_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_SEQ_HPP

#include "../config.hpp"

#include "rule_conjunction.hpp"
#include "skip_control.hpp"
#include "trivial.hpp"

#include "../apply_mode.hpp"
#include "../rewind_mode.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename... Rules >
         struct seq;

         template<>
         struct seq<>
            : trivial< true >
         {
         };

         template< typename Rule >
         struct seq< Rule >
         {
            using analyze_t = typename Rule::analyze_t;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               return Control< Rule >::template match< A, M, Action, Control >( in, st... );
            }
         };

         template< typename... Rules >
         struct seq
         {
            using analyze_t = analysis::generic< analysis::rule_type::SEQ, Rules... >;

            template< apply_mode A,
                      rewind_mode M,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            static bool match( Input& in, States&&... st )
            {
               auto m = in.template mark< M >();
               using m_t = decltype( m );
               return m( rule_conjunction< Rules... >::template match< A, m_t::next_rewind_mode, Action, Control >( in, st... ) );
            }
         };

         template< typename... Rules >
         struct skip_control< seq< Rules... > > : std::true_type
         {
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
