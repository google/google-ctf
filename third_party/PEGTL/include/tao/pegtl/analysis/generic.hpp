// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ANALYSIS_GENERIC_HPP
#define TAOCPP_PEGTL_INCLUDE_ANALYSIS_GENERIC_HPP

#include "../config.hpp"

#include "grammar_info.hpp"
#include "insert_rules.hpp"
#include "rule_type.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace analysis
      {
         template< rule_type Type, typename... Rules >
         struct generic
         {
            template< typename Name >
            static std::string insert( grammar_info& g )
            {
               const auto r = g.insert< Name >( Type );
               if( r.second ) {
                  insert_rules< Rules... >::insert( g, r.first->second );
               }
               return r.first->first;
            }
         };

      }  // namespace analysis

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
