// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_STRING_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_STRING_INPUT_HPP

#include <string>
#include <utility>

#include "config.hpp"
#include "eol.hpp"
#include "memory_input.hpp"
#include "tracking_mode.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct string_holder
         {
            const std::string data;

            template< typename T >
            explicit string_holder( T&& in_data )
               : data( std::forward< T >( in_data ) )
            {
            }
         };

      }  // namespace internal

      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf, typename Source = std::string >
      struct string_input
         : private internal::string_holder,
           public memory_input< P, Eol, Source >
      {
         template< typename T, typename... Ts >
         explicit string_input( T&& in_data, Ts&&... ts )
            : internal::string_holder( std::forward< T >( in_data ) ),
              memory_input< P, Eol, Source >( data.data(), data.size(), std::forward< Ts >( ts )... )
         {
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
