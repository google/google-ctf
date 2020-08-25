// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_CONTRIB_TRACER_HPP
#define TAOCPP_PEGTL_INCLUDE_CONTRIB_TRACER_HPP

#include <cassert>
#include <iomanip>
#include <iostream>
#include <utility>
#include <vector>

#include "../config.hpp"
#include "../normal.hpp"

#include "../internal/demangle.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      struct trace_state
      {
         unsigned rule = 0;
         unsigned line = 0;
         std::vector< unsigned > stack;
      };

      template< typename Rule >
      struct tracer
         : normal< Rule >
      {
         template< typename Input, typename... States >
         static void start( const Input& in, States&&... )
         {
            std::cerr << in.position() << "  start  " << internal::demangle< Rule >() << std::endl;
         }

         template< typename Input >
         static void start( const Input& in, trace_state& ts )
         {
            std::cerr << std::setw( 6 ) << ++ts.line << " " << std::setw( 6 ) << ++ts.rule << " " << in.position() << "  start  " << internal::demangle< Rule >() << std::endl;
            ts.stack.push_back( ts.rule );
         }

         template< typename Input, typename... States >
         static void success( const Input& in, States&&... )
         {
            std::cerr << in.position() << " success " << internal::demangle< Rule >() << std::endl;
         }

         template< typename Input >
         static void success( const Input& in, trace_state& ts )
         {
            assert( !ts.stack.empty() );
            std::cerr << std::setw( 6 ) << ++ts.line << " " << std::setw( 6 ) << ts.stack.back() << " " << in.position() << " success " << internal::demangle< Rule >() << std::endl;
            ts.stack.pop_back();
         }

         template< typename Input, typename... States >
         static void failure( const Input& in, States&&... )
         {
            std::cerr << in.position() << " failure " << internal::demangle< Rule >() << std::endl;
         }

         template< typename Input >
         static void failure( const Input& in, trace_state& ts )
         {
            assert( !ts.stack.empty() );
            std::cerr << std::setw( 6 ) << ++ts.line << " " << std::setw( 6 ) << ts.stack.back() << " " << in.position() << " failure " << internal::demangle< Rule >() << std::endl;
            ts.stack.pop_back();
         }

         template< template< typename... > class Action, typename Input, typename... States >
         static void apply0( const Input&, States&&... st )
         {
            std::cerr << "apply0 " << internal::demangle< Action< Rule > >() << std::endl;
            Action< Rule >::apply0( st... );
         }

         template< template< typename... > class Action, typename Input >
         static void apply0( const Input&, trace_state& ts )
         {
            std::cerr << std::setw( 6 ) << ++ts.line << "        " << internal::demangle< Action< Rule > >() << "::apply0()" << std::endl;
            Action< Rule >::apply0( ts );
         }

         template< template< typename... > class Action, typename Iterator, typename Input, typename... States >
         static void apply( const Iterator& begin, const Input& in, States&&... st )
         {
            std::cerr << "apply " << internal::demangle< Action< Rule > >() << std::endl;
            using action_t = typename Input::action_t;
            const action_t action_input( begin, in );
            Action< Rule >::apply( action_input, st... );
         }

         template< template< typename... > class Action, typename Iterator, typename Input >
         static void apply( const Iterator& begin, const Input& in, trace_state& ts )
         {
            std::cerr << std::setw( 6 ) << ++ts.line << "        " << internal::demangle< Action< Rule > >() << "::apply()" << std::endl;
            using action_t = typename Input::action_t;
            const action_t action_input( begin, in );
            Action< Rule >::apply( action_input, ts );
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
