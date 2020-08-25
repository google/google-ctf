// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#define TAOCPP_PEGTL_PRETTY_DEMANGLE 1

#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace proto3
      {
         // clang-format off

         struct comment : seq< two< '/' >, until< eolf > > {};
         struct sp : sor< space, comment > {};
         struct sps : star< sp > {};

         struct comma : one< ',' > {};
         struct dot : one< '.' > {};
         struct equ : one< '=' > {};
         struct semi : one< ';' > {};

         struct option;
         struct message;

         struct odigit : range< '0', '7' > {};

         struct ident_first : ranges< 'a', 'z', 'A', 'Z' > {};  // NOTE: Yes, no '_'.
         struct ident_other : ranges< 'a', 'z', 'A', 'Z', '0', '9', '_' > {};
         struct ident : seq< ident_first, star< ident_other > > {};
         struct full_ident : list_must< ident, dot > {};

         struct oct_lit : seq< one< '0' >, star< odigit > > {};
         struct hex_lit : seq< one< '0' >, one< 'x', 'X' >, plus< xdigit > > {};
         struct dec_lit : seq< range< '1', '9' >, star< digit > > {};
         struct int_lit : sor< dec_lit, hex_lit, oct_lit > {};

         struct hex_escape : if_must< one< 'x', 'X' >, xdigit, xdigit > {};
         struct oct_escape : if_must< odigit, odigit, odigit > {};
         struct char_escape : one< 'a', 'b', 'f', 'n', 'r', 't', 'v', '\\', '\'', '"' > {};
         struct escape : if_must< one< '\\' >, hex_escape, oct_escape, char_escape > {};
         struct char_value : sor< escape, not_one< '\n', '\0' > > {};  // NOTE: No need to exclude '\' from not_one<>, see escape rule.
         template< char Q >
         struct str_impl : if_must< one< Q >, until< one< Q >, char_value > > {};
         struct str_lit : sor< str_impl< '\'' >, str_impl< '"' > > {};

         struct bool_lit : seq< sor< string< 't', 'r', 'u', 'e' >, string< 'f', 'a', 'l', 's', 'e' > >, not_at< ident_other > > {};

         struct sign : one< '+', '-' > {};
         struct constant : sor< bool_lit, full_ident, seq< opt< sign >, int_lit >, str_lit > {};  // TODO: Needs sps after sign?

         struct option_name : seq< sor< ident, if_must< one< '(' >, full_ident, one< ')' > > >, star_must< dot, ident > > {};
         struct option : if_must< string< 'o', 'p', 't', 'i', 'o', 'n' >, sps, option_name, sps, equ, sps, constant, sps, semi, sps > {};

         struct bool_type : string< 'b', 'o', 'o', 'l' > {};
         struct bytes_type : string< 'b', 'y', 't', 'e', 's' > {};
         struct double_type : string< 'd', 'o', 'u', 'b', 'l', 'e' > {};
         struct float_type : string< 'f', 'l', 'o', 'a', 't' > {};
         struct string_type : string< 's', 't', 'r', 'i', 'n', 'g' > {};

         struct int32_type : string< 'i', 'n', 't', '3', '2' > {};
         struct int64_type : string< 'i', 'n', 't', '6', '4' > {};
         struct sint32_type : string< 's', 'i', 'n', 't', '3', '2' > {};
         struct sint64_type : string< 's', 'i', 'n', 't', '6', '4' > {};
         struct uint32_type : string< 'u', 'i', 'n', 't', '3', '2' > {};
         struct uint64_type : string< 'u', 'i', 'n', 't', '6', '4' > {};
         struct fixed32_type : string< 'f', 'i', 'x', 'e', 'd', '3', '2' > {};
         struct fixed64_type : string< 'f', 'i', 'x', 'e', 'd', '6', '4' > {};
         struct sfixed32_type : string< 's', 'f', 'i', 'x', 'e', 'd', '3', '2' > {};
         struct sfixed64_type : string< 's', 'f', 'i', 'x', 'e', 'd', '6', '4' > {};

         struct builtin_type : seq< sor< bool_type, bytes_type, double_type, float_type, string_type, int32_type, int64_type, sint32_type, sint64_type, uint32_type, uint64_type, fixed32_type, fixed64_type, sfixed32_type, sfixed64_type >, not_at< ident_other > > {};

         struct defined_type : seq< opt< dot >, full_ident > {};  // NOTE: This replaces both message_type and enum_type -- they have the same syntax.

         struct type : sor< builtin_type, defined_type > {};

         struct field_option : if_must< option_name, sps, equ, sps, constant > {};
         struct field_options : if_must< one< '[' >, sps, list< field_option, comma, sp >, sps, one< ']' > > {};
         struct field_name : ident {};
         struct field_number : int_lit {};
         struct field : seq< opt< string< 'r', 'e', 'p', 'e', 'a', 't', 'e', 'd' >, sps >, type, sps, field_name, sps, equ, sps, field_number, sps, opt< field_options, sps >, semi > {};

         struct oneof_name : ident {};
         struct oneof_field : if_must< type, sps, field_name, sps, equ, sps, field_number, sps, opt< field_options, sps >, semi > {};
         struct oneof_body : sor< oneof_field, semi > {};
         struct oneof : if_must< string< 'o', 'n', 'e', 'o', 'f' >, sps, oneof_name, sps, one< '{' >, sps, until< one< '}' >, oneof_body, sps >, sps > {};

         struct key_type : seq< sor< bool_type, string_type, int32_type, int64_type, sint32_type, sint64_type, uint32_type, uint64_type, fixed32_type, fixed64_type, sfixed32_type, sfixed64_type >, not_at< ident_other > > {};
         struct map_name : ident {};
         struct map_field : if_must< string< 'm', 'a', 'p' >, sps, one< '<' >, sps, key_type, sps, comma, sps, type, sps, one< '>' >, sps, map_name, sps, equ, sps, field_number, sps, opt< field_options, sps >, semi > {};

         struct range : if_must< int_lit, sps, string< 't', 'o' >, sps, sor< int_lit, string< 'm', 'a', 'x' > > > {};
         struct ranges : list_must< range, comma, sp > {};
         struct field_names : list_must< field_name, comma, sp > {};
         struct reserved : if_must< string< 'r', 'e', 's', 'e', 'r', 'v', 'e', 'd' >, sps, sor< ranges, field_names >, sps, semi > {};

         struct enum_name : ident {};
         struct enum_value_option : seq< option_name, sps, equ, sps, constant > {};
         struct enum_field : seq< ident, sps, equ, sps, int_lit, sps, opt< if_must< one< '[' >, sps, list_must< enum_value_option, comma, sp >, sps, one< ']' >, sps > >, semi > {};
         struct enum_body : if_must< one< '{' >, sps, star< sor< option, enum_field, semi >, sps >, one< '}' > > {};
         struct enum_ : if_must< string< 'e', 'n', 'u', 'm' >, sps, enum_name, sps, enum_body > {};

         struct message_thing : sor< field, enum_, message, option, oneof, map_field, reserved, semi > {};
         struct message : if_must< string< 'm', 'e', 's', 's', 'a', 'g', 'e' >, sps, ident, sps, one< '{' >, sps, star< message_thing, sps >, one< '}' >, sps > {};

         struct package : if_must< string< 'p', 'a', 'c', 'k', 'a', 'g', 'e' >, sps, full_ident, sps, semi, sps > {};

         struct import_option : opt< sor< string< 'w', 'e', 'a', 'k' >, string< 'p', 'u', 'b', 'l', 'i', 'c' > > > {};
         struct import : if_must< string< 'i', 'm', 'p', 'o', 'r', 't' >, sps, import_option, sps, str_lit, sps, semi, sps > {};

         struct rpc_name : ident {};
         struct rpc_type : if_must< one< '(' >, sps, opt< string< 's', 't', 'r', 'e', 'a', 'm' >, sps >, defined_type, sps, one< ')' > > {};
         struct rpc_options : if_must< one< '{' >, sps, star< sor< option, semi >, sps >, one< '}' > > {};
         struct rpc : if_must< string< 'r', 'p', 'c' >, sps, rpc_name, sps, rpc_type, sps, string< 'r', 'e', 't', 'u', 'r', 'n', 's' >, sps, rpc_type, sor< semi, rpc_options > > {};
         struct service_name : ident {};
         struct service : if_must< string< 's', 'e', 'r', 'v', 'i', 'c', 'e' >, sps, service_name, sps, one< '{' >, sps, list_must< sor< option, rpc, semi >, comma, sp >, sps, one< '}' > > {};

         struct body : sor< import, package, option, message, enum_, service, semi > {};

         struct head : if_must< string< 's', 'y', 'n', 't', 'a', 'x' >, sps, equ, sps, string< '"', 'p', 'r', 'o', 't', 'o', '3', '"' >, sps, semi > {};
         struct proto : must< sps, head, sps, star< body, sps >, eof > {};

         // clang-format on

      }  // namespace proto3

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

int main( int argc, char** argv )
{
   using namespace tao::TAOCPP_PEGTL_NAMESPACE;

   analyze< proto3::proto >();

   for( int i = 1; i < argc; ++i ) {
      file_input<> in( argv[ i ] );
      parse< proto3::proto >( in );
   }
   return 0;
}
