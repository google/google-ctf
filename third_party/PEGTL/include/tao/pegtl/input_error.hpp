// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INPUT_ERROR_HPP
#define TAOCPP_PEGTL_INCLUDE_INPUT_ERROR_HPP

#include <cerrno>
#include <sstream>
#include <stdexcept>

#include "config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      struct input_error
         : std::runtime_error
      {
         input_error( const std::string& message, const int in_errorno )
            : std::runtime_error( message ),
              errorno( in_errorno )
         {
         }

         int errorno;
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#define TAOCPP_PEGTL_THROW_INPUT_ERROR( MESSAGE )                           \
   do {                                                                     \
      const int errorno = errno;                                            \
      std::ostringstream oss;                                               \
      oss << "pegtl: " << MESSAGE << " errno " << errorno;                  \
      throw tao::TAOCPP_PEGTL_NAMESPACE::input_error( oss.str(), errorno ); \
   } while( false )

#endif
