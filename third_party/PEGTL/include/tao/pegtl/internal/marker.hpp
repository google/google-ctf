// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_INTERNAL_MARKER_HPP
#define TAOCPP_PEGTL_INCLUDE_INTERNAL_MARKER_HPP

#include "../config.hpp"
#include "../rewind_mode.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< typename Iterator, rewind_mode M >
         class marker
         {
         public:
            static constexpr rewind_mode next_rewind_mode = M;

            explicit marker( const Iterator& ) noexcept
            {
            }

            marker( marker&& ) noexcept
            {
            }

            marker( const marker& ) = delete;
            void operator=( const marker& ) = delete;

            bool operator()( const bool result ) const noexcept
            {
               return result;
            }
         };

         template< typename Iterator >
         class marker< Iterator, rewind_mode::REQUIRED >
         {
         public:
            static constexpr rewind_mode next_rewind_mode = rewind_mode::ACTIVE;

            explicit marker( Iterator& i ) noexcept
               : m_saved( i ),
                 m_input( &i )
            {
            }

            marker( marker&& i ) noexcept
               : m_saved( i.m_saved ),
                 m_input( i.m_input )
            {
               i.m_input = nullptr;
            }

            ~marker() noexcept
            {
               if( m_input != nullptr ) {
                  ( *m_input ) = m_saved;
               }
            }

            marker( const marker& ) = delete;
            void operator=( const marker& ) = delete;

            bool operator()( const bool result ) noexcept
            {
               if( result ) {
                  m_input = nullptr;
                  return true;
               }
               return false;
            }

            const Iterator& iterator() const noexcept
            {
               return m_saved;
            }

         private:
            const Iterator m_saved;
            Iterator* m_input;
         };

      }  // namespace internal

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
