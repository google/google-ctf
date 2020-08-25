// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace
      {
         std::string u16s( const char16_t u )
         {
            return std::string( reinterpret_cast< const char* >( &u ), sizeof( u ) );
         }

      }  // namespace

      void unit_test()
      {
         verify_rule< utf16::any >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, "\x01", result_type::LOCAL_FAILURE, 1 );
         verify_rule< utf16::any >( __LINE__, __FILE__, "\xff", result_type::LOCAL_FAILURE, 1 );

         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 1 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, "  ", result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0x00ff ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0x0100 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0x0fff ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0x1000 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd800 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd900 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xde00 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xfffe ) + " ", result_type::SUCCESS, 1 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xffff ) + "  ", result_type::SUCCESS, 2 );

         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd7ff ) + u16s( 0xdfff ), result_type::SUCCESS, 2 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xdc00 ) + u16s( 0xdfff ), result_type::SUCCESS, 2 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd800 ) + u16s( 0x0020 ), result_type::SUCCESS, 2 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd800 ) + u16s( 0xff20 ), result_type::SUCCESS, 2 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd800 ) + u16s( 0xdf00 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd800 ) + u16s( 0xdfff ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xd800 ) + u16s( 0xdfff ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xdbff ) + u16s( 0xdc00 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::any >( __LINE__, __FILE__, u16s( 0xdbff ) + u16s( 0xdfff ), result_type::SUCCESS, 0 );

         verify_rule< utf16::one< 0x20 > >( __LINE__, __FILE__, u16s( 0x20 ), result_type::SUCCESS, 0 );
         verify_rule< utf16::one< 0x20ac > >( __LINE__, __FILE__, u16s( 0x20ac ), result_type::SUCCESS, 0 );
         verify_rule< utf16::one< 0x10437 > >( __LINE__, __FILE__, u16s( 0xd801 ) + u16s( 0xdc37 ), result_type::SUCCESS, 0 );

         verify_rule< utf16::bom >( __LINE__, __FILE__, u16s( 0xfeff ), result_type::SUCCESS, 0 );
         verify_rule< utf16::bom >( __LINE__, __FILE__, u16s( 0xfffe ), result_type::LOCAL_FAILURE, 2 );

         verify_rule< utf16::string< 0x20, 0x20ac, 0x10437 > >( __LINE__, __FILE__, u16s( 0x20 ) + u16s( 0x20ac ) + u16s( 0xd801 ) + u16s( 0xdc37 ) + u16s( 0x20 ), result_type::SUCCESS, 2 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
