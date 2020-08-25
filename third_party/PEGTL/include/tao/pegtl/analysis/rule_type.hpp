// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_ANALYSIS_RULE_TYPE_HPP
#define TAOCPP_PEGTL_INCLUDE_ANALYSIS_RULE_TYPE_HPP

#include "../config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace analysis
      {
         enum class rule_type : char
         {
            ANY,  // Consumption-on-success is always true; assumes bounded repetition of conjunction of sub-rules.
            OPT,  // Consumption-on-success not necessarily true; assumes bounded repetition of conjunction of sub-rules.
            SEQ,  // Consumption-on-success depends on consumption of (non-zero bounded repetition of) conjunction of sub-rules.
            SOR   // Consumption-on-success depends on consumption of (non-zero bounded repetition of) disjunction of sub-rules.
         };

      }  // namespace analysis

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
