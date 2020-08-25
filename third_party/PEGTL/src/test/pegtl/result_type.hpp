// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_TEST_RESULT_TYPE_HPP
#define TAOCPP_PEGTL_INCLUDE_TEST_RESULT_TYPE_HPP

#include <ostream>

#include <tao/pegtl/config.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      enum class result_type
      {
         SUCCESS = 1,
         LOCAL_FAILURE = 0,
         GLOBAL_FAILURE = -1
      };

      inline std::ostream& operator<<( std::ostream& o, const result_type t )
      {
         switch( t ) {
            case result_type::SUCCESS:
               return o << "success";
            case result_type::LOCAL_FAILURE:
               return o << "local failure";
            case result_type::GLOBAL_FAILURE:
               return o << "global failure";
         }
         return o << int( t );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
