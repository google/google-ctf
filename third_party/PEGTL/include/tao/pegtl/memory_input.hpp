// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_MEMORY_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_MEMORY_INPUT_HPP

#include <cstddef>
#include <cstring>
#include <string>
#include <type_traits>
#include <utility>

#include "config.hpp"
#include "eol.hpp"
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
      namespace internal
      {
         template< tracking_mode, typename Eol, typename Source >
         class memory_input_base;

         template< typename Eol, typename Source >
         class memory_input_base< tracking_mode::IMMEDIATE, Eol, Source >
         {
         public:
            using iterator_t = internal::iterator;

            template< typename T >
            memory_input_base( const iterator_t& in_begin, const char* in_end, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
               : m_current( in_begin ),
                 m_end( in_end ),
                 m_source( std::forward< T >( in_source ) )
            {
            }

            template< typename T >
            memory_input_base( const char* in_begin, const char* in_end, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
               : m_current( in_begin ),
                 m_end( in_end ),
                 m_source( std::forward< T >( in_source ) )
            {
            }

            memory_input_base( const memory_input_base& ) = delete;
            memory_input_base operator=( const memory_input_base& ) = delete;

            const char* current() const noexcept
            {
               return m_current.data;
            }

            const char* end( const std::size_t = 0 ) const noexcept
            {
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

            TAOCPP_PEGTL_NAMESPACE::position position( const iterator_t& it ) const
            {
               return TAOCPP_PEGTL_NAMESPACE::position( it, m_source );
            }

         protected:
            iterator_t m_current;
            const char* const m_end;
            const Source m_source;
         };

         template< typename Eol, typename Source >
         class memory_input_base< tracking_mode::LAZY, Eol, Source >
         {
         public:
            using iterator_t = const char*;

            template< typename T >
            memory_input_base( const internal::iterator& in_begin, const char* in_end, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
               : m_begin( in_begin ),
                 m_current( in_begin.data ),
                 m_end( in_end ),
                 m_source( std::forward< T >( in_source ) )
            {
            }

            template< typename T >
            memory_input_base( const char* in_begin, const char* in_end, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
               : m_begin( in_begin ),
                 m_current( in_begin ),
                 m_end( in_end ),
                 m_source( std::forward< T >( in_source ) )
            {
            }

            memory_input_base( const memory_input_base& ) = delete;
            memory_input_base operator=( const memory_input_base& ) = delete;

            const char* current() const noexcept
            {
               return m_current;
            }

            const char* end( const std::size_t = 0 ) const noexcept
            {
               return m_end;
            }

            std::size_t byte() const noexcept
            {
               return std::size_t( current() - m_begin.data );
            }

            void bump( const std::size_t in_count = 1 ) noexcept
            {
               m_current += in_count;
            }

            void bump_in_this_line( const std::size_t in_count = 1 ) noexcept
            {
               m_current += in_count;
            }

            void bump_to_next_line( const std::size_t in_count = 1 ) noexcept
            {
               m_current += in_count;
            }

            TAOCPP_PEGTL_NAMESPACE::position position( const iterator_t it ) const
            {
               internal::iterator c( m_begin );
               internal::bump( c, std::size_t( it - m_begin.data ), Eol::ch );
               return TAOCPP_PEGTL_NAMESPACE::position( c, m_source );
            }

         protected:
            const internal::iterator m_begin;
            iterator_t m_current;
            const char* const m_end;
            const Source m_source;
         };

      }  // namespace internal

      template< tracking_mode P = tracking_mode::IMMEDIATE, typename Eol = eol::lf_crlf, typename Source = std::string >
      class memory_input
         : public internal::memory_input_base< P, Eol, Source >
      {
      public:
         static constexpr tracking_mode tracking_mode_v = P;

         using eol_t = Eol;
         using source_t = Source;

         using typename internal::memory_input_base< P, Eol, Source >::iterator_t;

         using action_t = internal::action_input< memory_input >;

         using internal::memory_input_base< P, Eol, Source >::memory_input_base;

         template< typename T >
         memory_input( const char* in_begin, const std::size_t in_size, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
            : memory_input( in_begin, in_begin + in_size, std::forward< T >( in_source ) )
         {
         }

         template< typename T >
         memory_input( const std::string& in_string, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
            : memory_input( in_string.data(), in_string.size(), std::forward< T >( in_source ) )
         {
         }

         template< typename T >
         memory_input( const char* in_begin, T&& in_source ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
            : memory_input( in_begin, std::strlen( in_begin ), std::forward< T >( in_source ) )
         {
         }

         template< typename T >
         memory_input( const char* in_begin, const char* in_end, T&& in_source, const std::size_t in_byte, const std::size_t in_line, const std::size_t in_byte_in_line ) noexcept( std::is_nothrow_constructible< Source, T&& >::value )
            : memory_input( { in_begin, in_byte, in_line, in_byte_in_line }, in_end, std::forward< T >( in_source ) )
         {
         }

         memory_input( const memory_input& ) = delete;
         memory_input operator=( const memory_input& ) = delete;

         const Source& source() const noexcept
         {
            return this->m_source;
         }

         bool empty() const noexcept
         {
            return this->current() == this->end();
         }

         std::size_t size( const std::size_t = 0 ) const noexcept
         {
            return std::size_t( this->end() - this->current() );
         }

         char peek_char( const std::size_t offset = 0 ) const noexcept
         {
            return this->current()[ offset ];
         }

         unsigned char peek_byte( const std::size_t offset = 0 ) const noexcept
         {
            return static_cast< unsigned char >( peek_char( offset ) );
         }

         iterator_t& iterator() noexcept
         {
            return this->m_current;
         }

         const iterator_t& iterator() const noexcept
         {
            return this->m_current;
         }

         using internal::memory_input_base< P, Eol, Source >::position;

         TAOCPP_PEGTL_NAMESPACE::position position() const
         {
            return position( iterator() );
         }

         void discard() const noexcept
         {
         }

         void require( const std::size_t ) const noexcept
         {
         }

         template< rewind_mode M >
         internal::marker< iterator_t, M > mark() noexcept
         {
            return internal::marker< iterator_t, M >( iterator() );
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
