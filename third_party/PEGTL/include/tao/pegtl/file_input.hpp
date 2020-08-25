// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_FILE_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_FILE_INPUT_HPP

#include "config.hpp"
#include "eol.hpp"
#include "tracking_mode.hpp"

#if defined( __unix__ ) || ( defined( __APPLE__ ) && defined( __MACH__ ) )
#include <unistd.h>  // Required for _POSIX_MAPPED_FILES
#endif

#if defined( _POSIX_MAPPED_FILES )
#include "mmap_input.hpp"
#else
#include "read_input.hpp"
#endif

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
#if defined( _POSIX_MAPPED_FILES )
      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
      using file_input = mmap_input< P, Eol >;
#else
      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf >
      using file_input = read_input< P, Eol >;
#endif

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
