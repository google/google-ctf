// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_DEMANGLE_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_DEMANGLE_HPP

#include <string>
#include <typeinfo>

#include "../config.hpp"

#if defined( __GLIBCXX__ )
#include "demangle_cxxabi.hpp"
#elif defined( __has_include )
// clang-format off
#if __has_include( <cxxabi.h> )
// clang-format on
#include "demangle_cxxabi.hpp"
#else
#include "demangle_nop.hpp"
#endif
#else
#include "demangle_nop.hpp"
#endif

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename T >
         std::string demangle()
         {
            return demangle( typeid( T ).name() );
         }

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
