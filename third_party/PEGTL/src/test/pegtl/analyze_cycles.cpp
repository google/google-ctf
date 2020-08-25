// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      template< typename... Rules >
      struct any_seq
         : public seq< Rules... >
      {
         using analyze_t = analysis::generic< analysis::rule_type::ANY, Rules... >;
      };

      void unit_test()
      {
         verify_analyze< eof >( __LINE__, __FILE__, false, false );
         verify_analyze< eolf >( __LINE__, __FILE__, false, false );
         verify_analyze< success >( __LINE__, __FILE__, false, false );
         verify_analyze< failure >( __LINE__, __FILE__, true, false );
         {
            struct tst : seq< eof, at< digit >, tst >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );  // This is a false positive.
         }
         {
            struct tst : sor< digit, seq< at< digit >, tst > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );  // This is a false positive.
         }
         {
            struct tst : sor< digit, seq< opt< digit >, tst > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : sor< digit, tst >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : at< any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : at< tst >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : at< any, tst >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : not_at< any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : opt< tst >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : opt< any, tst >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct rec : sor< seq< rec, alpha >, alpha >
            {
            };
            verify_analyze< rec >( __LINE__, __FILE__, true, true );
         }
         {
            struct bar;
            struct foo : seq< digit, bar >
            {
            };
            struct bar : plus< foo >
            {
            };
            verify_analyze< seq< any, bar > >( __LINE__, __FILE__, true, false );
         }
         {
            struct bar;
            struct foo : seq< bar, digit >
            {
            };
            struct bar : plus< foo >
            {
            };
            verify_analyze< seq< bar, any > >( __LINE__, __FILE__, true, true );
         }
         {
            struct bar;
            struct foo : sor< digit, bar >
            {
            };
            struct bar : plus< foo >
            {
            };
            verify_analyze< bar >( __LINE__, __FILE__, false, true );
            verify_analyze< foo >( __LINE__, __FILE__, false, true );
            verify_analyze< sor< any, bar > >( __LINE__, __FILE__, false, true );
         }
         {
            // Excerpt from the Lua 5.3 grammar:
            //  prefixexp ::= var | functioncall | ‘(’ exp ‘)’
            //  functioncall ::=  prefixexp args | prefixexp ‘:’ Name args
            //  var ::=  Name | prefixexp ‘[’ exp ‘]’ | prefixexp ‘.’ Name
            // Simplified version, equivalent regarding consumption of input:
            struct var;
            struct fun;
            struct exp : sor< var, fun, seq< any, exp, any > >
            {
            };
            struct fun : seq< exp, any >
            {
            };
            struct var : sor< any, seq< exp, any, exp >, seq< exp, any > >
            {
            };
            verify_analyze< exp >( __LINE__, __FILE__, true, true );
            verify_analyze< fun >( __LINE__, __FILE__, true, true );
            verify_analyze< var >( __LINE__, __FILE__, true, true );
         }
         {
            struct exp : sor< exp, seq< any, exp > >
            {
            };
            verify_analyze< exp >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : until< any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : until< star< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : until< any, star< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, true );
         }
         {
            struct tst : until< star< any >, star< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : until< star< any >, star< any > >
            {
            };
            verify_analyze< any_seq< tst > >( __LINE__, __FILE__, true, true );
         }
         {
            struct tst : until< any, any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : until< star< any >, any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : plus< plus< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : star< star< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : plus< star< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : plus< opt< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : star< opt< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : star< plus< opt< any > > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : list< any, any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : list< star< any >, any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : list< any, opt< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : list< star< any >, opt< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : list_must< any, any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : list_must< star< any >, any >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : list_must< any, opt< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, true, false );
         }
         {
            struct tst : list_must< star< any >, opt< any > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : plus< pad_opt< alpha, digit > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
         {
            struct tst : rep< 42, opt< alpha > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, false );
         }
         {
            struct tst : rep_min< 42, opt< alpha > >
            {
            };
            verify_analyze< tst >( __LINE__, __FILE__, false, true );
         }
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
