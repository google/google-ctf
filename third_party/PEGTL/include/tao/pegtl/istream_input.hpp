// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ISTREAM_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_ISTREAM_INPUT_HPP

#include <istream>

#include "buffer_input.hpp"
#include "config.hpp"
#include "eol.hpp"

#include "internal/istream_reader.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Eol = eol::lf_crlf >
      struct istream_input
         : buffer_input< internal::istream_reader, Eol >
      {
         template< typename T >
         istream_input( std::istream& in_stream, const std::size_t in_maximum, T&& in_source )
            : buffer_input< internal::istream_reader, Eol >( std::forward< T >( in_source ), in_maximum, in_stream )
         {
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
