// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_ACTION_INPUT_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_ACTION_INPUT_HPP

#include <cstddef>
#include <string>

#include "iterator.hpp"

#include "../config.hpp"
#include "../position.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         inline const char* begin_c_ptr( const char* p ) noexcept
         {
            return p;
         }

         inline const char* begin_c_ptr( const iterator& it ) noexcept
         {
            return it.data;
         }

         template< typename Input >
         class action_input
         {
         public:
            using input_t = Input;
            using iterator_t = typename Input::iterator_t;

            action_input( const iterator_t& in_begin, const Input& in_input ) noexcept
               : m_begin( in_begin ),
                 m_input( in_input )
            {
            }

            action_input( const action_input& ) = delete;
            action_input& operator=( const action_input& ) = delete;

            const iterator_t& iterator() const noexcept
            {
               return m_begin;
            }

            const Input& input() const noexcept
            {
               return m_input;
            }

            const char* begin() const noexcept
            {
               return begin_c_ptr( iterator() );
            }

            const char* end() const noexcept
            {
               return input().current();
            }

            bool empty() const noexcept
            {
               return begin() == end();
            }

            std::size_t size() const noexcept
            {
               return std::size_t( end() - begin() );
            }

            std::string string() const
            {
               return std::string( begin(), end() );
            }

            char peek_char( const std::size_t offset = 0 ) const noexcept
            {
               return begin()[ offset ];
            }

            unsigned char peek_byte( const std::size_t offset = 0 ) const noexcept
            {
               return static_cast< unsigned char >( peek_char( offset ) );
            }

            TAOCPP_PEGTL_NAMESPACE::position position() const noexcept
            {
               return input().position( iterator() );  // NOTE: Not efficient with LAZY inputs.
            }

         protected:
            const iterator_t m_begin;
            const Input& m_input;
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
