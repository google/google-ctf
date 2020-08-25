// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_BUFFER_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_BUFFER_INPUT_HPP

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>

#include "config.hpp"
#include "eol.hpp"
#include "memory_input.hpp"
#include "position.hpp"
#include "tracking_mode.hpp"

#include "internal/action_input.hpp"
#include "internal/bump_impl.hpp"
#include "internal/iterator.hpp"
#include "internal/marker.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename Reader, typename Eol = eol::lf_crlf, typename Source = std::string >
      class buffer_input
      {
      public:
         static constexpr tracking_mode tracking_mode_v = tracking_mode::IMMEDIATE;
         using reader_t = Reader;

         using eol_t = Eol;
         using source_t = Source;

         using iterator_t = internal::iterator;

         using action_t = internal::action_input< buffer_input >;

         template< typename T, typename... As >
         buffer_input( T&& in_source, const std::size_t maximum, As&&... as )
            : m_reader( std::forward< As >( as )... ),
              m_maximum( maximum ),
              m_buffer( new char[ maximum ] ),
              m_current( m_buffer.get() ),
              m_end( m_buffer.get() ),
              m_source( std::forward< T >( in_source ) )
         {
         }

         buffer_input( const buffer_input& ) = delete;
         void operator=( const buffer_input& ) = delete;

         bool empty()
         {
            require( 1 );
            return m_current.data == m_end;
         }

         std::size_t size( const std::size_t amount )
         {
            require( amount );
            return std::size_t( m_end - m_current.data );
         }

         const char* current() const noexcept
         {
            return m_current.data;
         }

         const char* end( const std::size_t amount )
         {
            require( amount );
            return m_end;
         }

         std::size_t byte() const noexcept
         {
            return m_current.byte;
         }

         std::size_t line() const noexcept
         {
            return m_current.line;
         }

         std::size_t byte_in_line() const noexcept
         {
            return m_current.byte_in_line;
         }

         const Source& source() const noexcept
         {
            return m_source;
         }

         char peek_char( const std::size_t offset = 0 ) const noexcept
         {
            return m_current.data[ offset ];
         }

         unsigned char peek_byte( const std::size_t offset = 0 ) const noexcept
         {
            return static_cast< unsigned char >( peek_char( offset ) );
         }

         void bump( const std::size_t in_count = 1 ) noexcept
         {
            internal::bump( m_current, in_count, Eol::ch );
         }

         void bump_in_this_line( const std::size_t in_count = 1 ) noexcept
         {
            internal::bump_in_this_line( m_current, in_count );
         }

         void bump_to_next_line( const std::size_t in_count = 1 ) noexcept
         {
            internal::bump_to_next_line( m_current, in_count );
         }

         void discard() noexcept
         {
            const auto s = m_end - m_current.data;
            std::memmove( m_buffer.get(), m_current.data, s );
            m_current.data = m_buffer.get();
            m_end = m_buffer.get() + s;
         }

         void require( const std::size_t amount )
         {
            if( m_current.data + amount > m_end ) {
               if( m_current.data + amount <= m_buffer.get() + m_maximum ) {
                  if( const auto r = m_reader( const_cast< char* >( m_end ), amount - std::size_t( m_end - m_current.data ) ) ) {
                     m_end += r;
                  }
                  else {
                     m_maximum = 0;
                  }
               }
            }
         }

         template< rewind_mode M >
         internal::marker< iterator_t, M > mark() noexcept
         {
            return internal::marker< iterator_t, M >( m_current );
         }

         TAOCPP_PEGTL_NAMESPACE::position position( const iterator_t& it ) const
         {
            return TAOCPP_PEGTL_NAMESPACE::position( it, m_source );
         }

         TAOCPP_PEGTL_NAMESPACE::position position() const
         {
            return position( m_current );
         }

         const iterator_t& iterator() const noexcept
         {
            return m_current;
         }

      private:
         Reader m_reader;
         std::size_t m_maximum;
         std::unique_ptr< char[] > m_buffer;
         iterator_t m_current;
         const char* m_end;
         const Source m_source;
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
