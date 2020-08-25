// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      int at_counter = 0;

      template< typename Rule >
      struct at_action
         : public nothing< Rule >
      {
      };

      template<>
      struct at_action< any >
      {
         template< typename Input >
         static void apply( const Input& /*unused*/ )
         {
            ++at_counter;
         }
      };

      void unit_test()
      {
         TAOCPP_PEGTL_TEST_ASSERT( at_counter == 0 );

         verify_analyze< at< eof > >( __LINE__, __FILE__, false, false );
         verify_analyze< at< any > >( __LINE__, __FILE__, false, false );

         verify_rule< at< eof > >( __LINE__, __FILE__, "", result_type::SUCCESS, 0 );
         verify_rule< at< eof > >( __LINE__, __FILE__, "a", result_type::LOCAL_FAILURE, 1 );
         verify_rule< at< any > >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< at< any > >( __LINE__, __FILE__, "a", result_type::SUCCESS, 1 );
         verify_rule< at< any > >( __LINE__, __FILE__, "aa", result_type::SUCCESS, 2 );
         verify_rule< at< any > >( __LINE__, __FILE__, "aaaa", result_type::SUCCESS, 4 );
         verify_rule< must< at< alpha > > >( __LINE__, __FILE__, "1", result_type::GLOBAL_FAILURE, 1 );
         verify_rule< must< at< alpha, alpha > > >( __LINE__, __FILE__, "a1a", result_type::GLOBAL_FAILURE, 3 );
         {
            memory_input<> in( "f", 1, __FILE__ );
            parse< any, at_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( at_counter == 1 );
         }
         {
            memory_input<> in( "f", 1, __FILE__ );
            parse< at< any >, at_action >( in );
            TAOCPP_PEGTL_TEST_ASSERT( at_counter == 1 );
         }
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
