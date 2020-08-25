// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ANALYSIS_ANALYZE_CYCLES_HPP
#define TAOCPP_PEGTL_INCLUDE_ANALYSIS_ANALYZE_CYCLES_HPP

#include <cassert>

#include <map>
#include <set>

#include <iostream>
#include <utility>

#include "../config.hpp"

#include "grammar_info.hpp"
#include "insert_guard.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace analysis
      {
         class analyze_cycles_impl
         {
         protected:
            explicit analyze_cycles_impl( const bool verbose ) noexcept
               : m_verbose( verbose ),
                 m_problems( 0 )
            {
            }

            const bool m_verbose;
            unsigned m_problems;
            grammar_info m_info;
            std::set< std::string > m_stack;
            std::map< std::string, bool > m_cache;
            std::map< std::string, bool > m_results;

            const std::map< std::string, rule_info >::const_iterator find( const std::string& name ) const noexcept
            {
               const auto iter = m_info.map.find( name );
               assert( iter != m_info.map.end() );
               return iter;
            }

            bool work( const std::map< std::string, rule_info >::const_iterator& start, const bool accum )
            {
               const auto j = m_cache.find( start->first );

               if( j != m_cache.end() ) {
                  return j->second;
               }
               if( const auto g = make_insert_guard( m_stack, start->first ) ) {
                  switch( start->second.type ) {
                     case rule_type::ANY: {
                        bool a = false;
                        for( const auto& r : start->second.rules ) {
                           a = a || work( find( r ), accum || a );
                        }
                        return m_cache[ start->first ] = true;
                     }
                     case rule_type::OPT: {
                        bool a = false;
                        for( const auto& r : start->second.rules ) {
                           a = a || work( find( r ), accum || a );
                        }
                        return m_cache[ start->first ] = false;
                     }
                     case rule_type::SEQ: {
                        bool a = false;
                        for( const auto& r : start->second.rules ) {
                           a = a || work( find( r ), accum || a );
                        }
                        return m_cache[ start->first ] = a;
                     }
                     case rule_type::SOR: {
                        bool a = true;
                        for( const auto& r : start->second.rules ) {
                           a = a && work( find( r ), accum );
                        }
                        return m_cache[ start->first ] = a;
                     }
                  }
                  throw std::runtime_error( "code should be unreachable" );  // LCOV_EXCL_LINE
               }
               if( !accum ) {
                  ++m_problems;
                  if( m_verbose ) {
                     std::cout << "problem: cycle without progress detected at rule class " << start->first << std::endl;  // LCOV_EXCL_LINE
                  }
               }
               return m_cache[ start->first ] = accum;
            }
         };

         template< typename Grammar >
         class analyze_cycles
            : private analyze_cycles_impl
         {
         public:
            explicit analyze_cycles( const bool verbose )
               : analyze_cycles_impl( verbose )
            {
               Grammar::analyze_t::template insert< Grammar >( m_info );
            }

            std::size_t problems()
            {
               for( auto i = m_info.map.begin(); i != m_info.map.end(); ++i ) {
                  m_results[ i->first ] = work( i, false );
                  m_cache.clear();
               }
               return m_problems;
            }

            template< typename Rule >
            bool consumes() const noexcept
            {
               const auto i = m_results.find( internal::demangle< Rule >() );
               assert( i != m_results.end() );
               return i->second;
            }
         };

      }  // namespace analysis

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
