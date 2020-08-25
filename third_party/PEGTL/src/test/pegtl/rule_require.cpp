// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< require< 0 > >( __LINE__, __FILE__, false, false );
         verify_analyze< require< 1 > >( __LINE__, __FILE__, false, false );
         verify_analyze< require< 9 > >( __LINE__, __FILE__, false, false );

         verify_rule< require< 0 > >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< require< 0 > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 1 );
         verify_rule< require< 0 > >( __LINE__, __FILE__, "  ", result_type::SUCCESS, 2 );
         verify_rule< require< 1 > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< require< 1 > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 1 );
         verify_rule< require< 1 > >( __LINE__, __FILE__, "  ", result_type::SUCCESS, 2 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "1", result_type::LOCAL_FAILURE, 1 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "12", result_type::LOCAL_FAILURE, 2 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "123", result_type::LOCAL_FAILURE, 3 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "1234", result_type::LOCAL_FAILURE, 4 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "12345", result_type::LOCAL_FAILURE, 5 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "123456", result_type::LOCAL_FAILURE, 6 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "1234567", result_type::LOCAL_FAILURE, 7 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "12345678", result_type::LOCAL_FAILURE, 8 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "123456789", result_type::SUCCESS, 9 );
         verify_rule< require< 9 > >( __LINE__, __FILE__, "123456789123456789", result_type::SUCCESS, 18 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
