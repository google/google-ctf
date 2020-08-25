// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace
      {
         std::string u32s( const char32_t u )
         {
            return std::string( reinterpret_cast< const char* >( &u ), sizeof( u ) );
         }

      }  // namespace

      void unit_test()
      {
         verify_rule< utf32::any >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, "\xff", result_type::LOCAL_FAILURE, 1 );
         verify_rule< utf32::any >( __LINE__, __FILE__, "\xff\xff", result_type::LOCAL_FAILURE, 2 );
         verify_rule< utf32::any >( __LINE__, __FILE__, "\xff\xff\xff", result_type::LOCAL_FAILURE, 3 );

         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0 ), result_type::SUCCESS, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 1 ), result_type::SUCCESS, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x00ff ) + " ", result_type::SUCCESS, 1 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x0100 ) + "  ", result_type::SUCCESS, 2 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x0fff ) + "   ", result_type::SUCCESS, 3 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x1000 ) + "    ", result_type::SUCCESS, 4 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0xfffe ), result_type::SUCCESS, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0xffff ), result_type::SUCCESS, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x100000 ), result_type::SUCCESS, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x10fffe ), result_type::SUCCESS, 0 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x10ffff ), result_type::SUCCESS, 0 );

         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x110000 ), result_type::LOCAL_FAILURE, 4 );
         verify_rule< utf32::any >( __LINE__, __FILE__, u32s( 0x110000 ) + u32s( 0 ), result_type::LOCAL_FAILURE, 8 );

         verify_rule< utf32::one< 0x20 > >( __LINE__, __FILE__, u32s( 0x20 ), result_type::SUCCESS, 0 );
         verify_rule< utf32::one< 0x20ac > >( __LINE__, __FILE__, u32s( 0x20ac ), result_type::SUCCESS, 0 );
         verify_rule< utf32::one< 0x10fedc > >( __LINE__, __FILE__, u32s( 0x10fedc ), result_type::SUCCESS, 0 );

         verify_rule< utf32::string< 0x20, 0x20ac, 0x10fedc > >( __LINE__, __FILE__, u32s( 0x20 ) + u32s( 0x20ac ) + u32s( 0x10fedc ) + u32s( 0x20 ), result_type::SUCCESS, 4 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
