// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_FILE_OPENER_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_FILE_OPENER_HPP

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <utility>

#include "../config.hpp"
#include "../input_error.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         struct file_opener
         {
            explicit file_opener( const char* filename )
               : m_source( filename ),
                 m_fd( open() )
            {
            }

            ~file_opener() noexcept
            {
               ::close( m_fd );
            }

            file_opener( const file_opener& ) = delete;
            void operator=( const file_opener& ) = delete;

            std::size_t size() const
            {
               struct stat st;
               errno = 0;
               if(::fstat( m_fd, &st ) < 0 ) {
                  TAOCPP_PEGTL_THROW_INPUT_ERROR( "unable to fstat() file " << m_source << " descriptor " << m_fd );
               }
               return std::size_t( st.st_size );
            }

            const char* const m_source;
            const int m_fd;

         private:
            int open() const
            {
               errno = 0;
               const int fd = ::open( m_source, O_RDONLY );
               if( fd >= 0 ) {
                  return fd;
               }
               TAOCPP_PEGTL_THROW_INPUT_ERROR( "unable to open() file " << m_source << " for reading" );
            }
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
