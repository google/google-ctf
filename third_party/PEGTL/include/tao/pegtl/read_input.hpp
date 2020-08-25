// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_READ_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_READ_INPUT_HPP

#include <string>

#include "config.hpp"
#include "eol.hpp"
#include "string_input.hpp"
#include "tracking_mode.hpp"

#include "internal/file_reader.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct filename_holder
         {
            const std::string filename;

            template< typename T >
            explicit filename_holder( T&& in_filename )
               : filename( std::forward< T >( in_filename ) )
            {
            }
         };

      }  // namespace internal

      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
      struct read_input
         : private internal::filename_holder,
           public string_input< P, Eol, const char* >
      {
         template< typename T >
         explicit read_input( T&& in_filename )
            : internal::filename_holder( std::forward< T >( in_filename ) ),
              string_input< P, Eol, const char* >( internal::file_reader( filename.c_str() ).read(), filename.c_str() )
         {
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
