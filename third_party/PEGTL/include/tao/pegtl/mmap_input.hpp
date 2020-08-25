// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_MMAP_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_MMAP_INPUT_HPP

#include <string>
#include <utility>

#include "config.hpp"
#include "eol.hpp"
#include "memory_input.hpp"
#include "tracking_mode.hpp"

#include "internal/file_mapper.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct mmap_holder
         {
            const std::string filename;
            const file_mapper data;

            template< typename T >
            mmap_holder( T&& in_filename )
               : filename( std::forward< T >( in_filename ) ),
                 data( filename.c_str() )
            {
            }
         };

      }  // namespace internal

      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
      struct mmap_input
         : private internal::mmap_holder,
           public memory_input< P, Eol, const char* >
      {
         template< typename T >
         explicit mmap_input( T&& in_filename )
            : internal::mmap_holder( std::forward< T >( in_filename ) ),
              memory_input< P, Eol, const char* >( data.begin(), data.end(), filename.c_str() )
         {
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
