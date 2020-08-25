// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, true, false );

         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "foo", result_type::SUCCESS, 0 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "foo ", result_type::SUCCESS, 1 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "foo foo", result_type::SUCCESS, 4 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "FOO", result_type::LOCAL_FAILURE, 3 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "f", result_type::LOCAL_FAILURE, 1 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "fo", result_type::LOCAL_FAILURE, 2 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, " foo", result_type::LOCAL_FAILURE, 4 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "foo_", result_type::LOCAL_FAILURE, 4 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "foo1", result_type::LOCAL_FAILURE, 4 );
         verify_rule< keyword< 'f', 'o', 'o' > >( __LINE__, __FILE__, "fooa", result_type::LOCAL_FAILURE, 4 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
