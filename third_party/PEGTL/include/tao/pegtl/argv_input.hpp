// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ARGV_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_ARGV_INPUT_HPP

#include <cstddef>
#include <sstream>
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
         inline std::string make_argv_source( const std::size_t argn )
         {
            std::ostringstream os;
            os << "argv[" << argn << ']';
            return os.str();
         }

      }  // namespace internal

      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
      struct argv_input
         : public memory_input< P, Eol >
      {
         template< typename T >
         argv_input( char** argv, const std::size_t argn, T&& in_source )
            : memory_input< P, Eol >( static_cast< const char* >( argv[ argn ] ), std::forward< T >( in_source ) )
         {
         }

         argv_input( char** argv, const std::size_t argn )
            : argv_input( argv, argn, internal::make_argv_source( argn ) )
         {
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
