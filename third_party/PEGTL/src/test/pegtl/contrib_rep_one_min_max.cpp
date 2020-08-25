// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/contrib/rep_one_min_max.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< ellipsis >( __LINE__, __FILE__, true, false );

         verify_analyze< rep_one_min_max< 0, 1, '+' > >( __LINE__, __FILE__, false, false );
         verify_analyze< rep_one_min_max< 1, 1, '+' > >( __LINE__, __FILE__, true, false );

         verify_rule< ellipsis >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< ellipsis >( __LINE__, __FILE__, ".", result_type::LOCAL_FAILURE, 1 );
         verify_rule< ellipsis >( __LINE__, __FILE__, "..", result_type::LOCAL_FAILURE, 2 );
         verify_rule< ellipsis >( __LINE__, __FILE__, "....", result_type::LOCAL_FAILURE, 4 );
         verify_rule< ellipsis >( __LINE__, __FILE__, "...", result_type::SUCCESS, 0 );
         verify_rule< ellipsis >( __LINE__, __FILE__, "... ", result_type::SUCCESS, 1 );
         verify_rule< ellipsis >( __LINE__, __FILE__, "...+", result_type::SUCCESS, 1 );
         verify_rule< ellipsis >( __LINE__, __FILE__, "...a", result_type::SUCCESS, 1 );

         verify_rule< rep_one_min_max< 0, 2, '+' > >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< rep_one_min_max< 0, 2, '+' > >( __LINE__, __FILE__, "-", result_type::SUCCESS, 1 );
         verify_rule< rep_one_min_max< 0, 2, '+' > >( __LINE__, __FILE__, "+-", result_type::SUCCESS, 1 );
         verify_rule< rep_one_min_max< 0, 2, '+' > >( __LINE__, __FILE__, "++-", result_type::SUCCESS, 1 );
         verify_rule< rep_one_min_max< 0, 2, '+' > >( __LINE__, __FILE__, "+++", result_type::LOCAL_FAILURE, 3 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
