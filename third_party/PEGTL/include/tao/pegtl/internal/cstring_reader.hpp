// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_CSTRING_READER_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_CSTRING_READER_HPP

#include <cassert>
#include <cstddef>

#include "../config.hpp"
#include "../input_error.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct cstring_reader
         {
            explicit cstring_reader( const char* zero_terminated ) noexcept
               : m_cstring( zero_terminated )
            {
               assert( m_cstring );
            }

            std::size_t operator()( char* buffer, const std::size_t length ) noexcept
            {
               std::size_t i = 0;
               char c;

               while( ( i < length ) && ( ( c = m_cstring[ i ] ) != 0 ) ) {
                  *buffer++ = c;
                  ++i;
               }
               m_cstring += i;
               return i;
            }

            const char* m_cstring;
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
