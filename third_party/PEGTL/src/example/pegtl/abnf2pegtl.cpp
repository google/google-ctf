// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <algorithm>
#include <iostream>
#include <iterator>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <cctype>
#include <cstdlib>
#include <cstring>

#include <tao/pegtl.hpp>
#include <tao/pegtl/analyze.hpp>
#include <tao/pegtl/contrib/abnf.hpp>

#define TAOCPP_PEGTL_STRINGIFY_IMPL( X ) #X
#define TAOCPP_PEGTL_STRINGIFY( X ) TAOCPP_PEGTL_STRINGIFY_IMPL( X )

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace abnf
      {
         namespace grammar
         {
            // ABNF grammar according to RFC 5234, updated by RFC 7405, with
            // the following differences:
            //
            // To form a C++ identifier from a rulename, all minuses are
            // replaced with underscores.
            //
            // As C++ identifiers are case-sensitive, we remember the "correct"
            // spelling from the first occurrence of a rulename, all other
            // occurrences are automatically changed to that.
            //
            // Certain rulenames are reserved as their equivalent C++ identifier is
            // reserved as a keyword, an alternative token, by the standard or
            // for other, special reasons.
            //
            // When using numerical values (num-val, repeat), the values
            // must be in the range of the corresponsing C++ data type.
            //
            // Remember we are defining a PEG, not a CFG. Simply copying some
            // ABNF from somewhere might lead to surprising results as the
            // alternations are now sequential, using the sor<> rule.
            //
            // PEG also require two extensions: the and-predicate and the
            // not-predicate. They are expressed by '&' and '!' respectively,
            // being allowed (optionally, only one of them) before the
            // repetition. You can use braces for more complex expressions.
            //
            // Finally, instead of the pre-defined CRLF sequence, we accept
            // any type of line ending as a convencience extension:

            // clang-format off
            struct CRLF : sor< abnf::CRLF, CR, LF > {};

            // The rest is according to the RFC(s):
            struct comment_cont : until< CRLF, sor< WSP, VCHAR > > {};
            struct comment : if_must< one< ';' >, comment_cont > {};
            struct c_nl : sor< comment, CRLF > {};
            struct c_wsp : sor< WSP, seq< c_nl, WSP > > {};

            struct rulename : seq< ALPHA, star< ranges< 'a', 'z', 'A', 'Z', '0', '9', '-' > > > {};

            struct quoted_string_cont : until< DQUOTE, print > {};
            struct quoted_string : if_must< DQUOTE, quoted_string_cont > {};
            struct case_insensitive_string : seq< opt< istring< '%', 'i' > >, quoted_string > {};
            struct case_sensitive_string : seq< istring< '%', 's' >, quoted_string > {};
            struct char_val : sor< case_insensitive_string, case_sensitive_string > {};

            struct prose_val_cont : until< one< '>' >, print > {};
            struct prose_val : if_must< one< '<' >, prose_val_cont > {};

            template< char First, typename Digit >
            struct gen_val
            {
               struct value : plus< Digit > {};
               struct range : if_must< one< '-' >, value > {};
               struct next_value : must< value > {};
               struct type : seq< istring< First >, must< value >, sor< range, star< one< '.' >, next_value > > > {};
            };

            using hex_val = gen_val< 'x', HEXDIG >;
            using dec_val = gen_val< 'd', DIGIT >;
            using bin_val = gen_val< 'b', BIT >;

            struct num_val_choice : sor< bin_val::type, dec_val::type, hex_val::type > {};
            struct num_val : if_must< one< '%' >, num_val_choice > {};

            struct alternation;
            struct option_close : one< ']' > {};
            struct option : seq< one< '[' >, pad< must< alternation >, c_wsp >, must< option_close > > {};
            struct group_close : one< ')' > {};
            struct group : seq< one< '(' >, pad< must< alternation >, c_wsp >, must< group_close > > {};
            struct rulename_val : rulename {};
            struct element : sor< rulename_val, group, option, char_val, num_val, prose_val > {};

            struct repeat : sor< seq< star< DIGIT >, one< '*' >, star< DIGIT > >, plus< DIGIT > > {};
            struct repetition : seq< opt< repeat >, element > {};

            struct and_predicate : if_must< one< '&' >, repetition > {};
            struct not_predicate : if_must< one< '!' >, repetition > {};
            struct predicate : sor< and_predicate, not_predicate, repetition > {};

            struct push_stack : success {};
            struct concatenation : seq< push_stack, list< predicate, plus< c_wsp > > > {};
            struct alternation : seq< push_stack, list_must< concatenation, pad< one< '/' >, c_wsp > > > {};

            struct defined_as_op : sor< string< '=', '/' >, one< '=' > > {};
            struct defined_as : pad< defined_as_op, c_wsp > {};
            struct rule : seq< push_stack, if_must< rulename, defined_as, alternation >, star< c_wsp >, must< c_nl > > {};
            struct rulelist : until< eof, sor< seq< star< c_wsp >, c_nl >, must< rule > > > {};

            // end of grammar

            template< typename Rule >
            struct error_control : normal< Rule >
            {
               static const std::string error_message;

               template< typename Input, typename... States >
               static void raise( const Input& in, States&&... /*unused*/ )
               {
                  throw parse_error( error_message, in );
               }
            };

            template<> const std::string error_control< comment_cont >::error_message = "unterminated comment";

            template<> const std::string error_control< quoted_string_cont >::error_message = "unterminated string (missing '\"')";
            template<> const std::string error_control< prose_val_cont >::error_message = "unterminated prose description (missing '>')";

            template<> const std::string error_control< hex_val::value >::error_message = "expected hexadecimal value";
            template<> const std::string error_control< dec_val::value >::error_message = "expected decimal value";
            template<> const std::string error_control< bin_val::value >::error_message = "expected binary value";
            template<> const std::string error_control< num_val_choice >::error_message = "expected base specifier (one of 'bBdDxX')";

            template<> const std::string error_control< option_close >::error_message = "unterminated option (missing ']')";
            template<> const std::string error_control< group_close >::error_message = "unterminated group (missing ')')";

            template<> const std::string error_control< repetition >::error_message = "expected element";
            template<> const std::string error_control< concatenation >::error_message = "expected element";
            template<> const std::string error_control< alternation >::error_message = "expected element";

            template<> const std::string error_control< defined_as >::error_message = "expected '=' or '=/'";
            template<> const std::string error_control< c_nl >::error_message = "unterminated rule";
            template<> const std::string error_control< rule >::error_message = "expected rule";
            // clang-format on

         }  // namespace grammar

      }  // namespace abnf

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

namespace abnf2pegtl
{
   struct data
   {
      std::string rulename;
      std::vector< std::vector< std::string > > elements;

      using rules_t = std::vector< std::pair< std::string, std::string > >;
      rules_t rules;

      rules_t::reverse_iterator find_rule( const std::string& v, const rules_t::reverse_iterator& rbegin )
      {
         return std::find_if( rbegin, rules.rend(), [&]( const rules_t::value_type& p ) { return ::strcasecmp( p.first.c_str(), v.c_str() ) == 0; } );
      }

      rules_t::reverse_iterator find_rule( const std::string& v )
      {
         return find_rule( v, rules.rbegin() );
      }
   };

   namespace
   {
      // clang-format off
      std::set< std::string > keywords = {
         "alignas", "alignof", "and", "and_eq",
         "asm", "auto", "bitand", "bitor",
         "bool", "break", "case", "catch",
         "char", "char16_t", "char32_t", "class",
         "compl", "const", "constexpr", "const_cast",
         "continue", "decltype", "default", "delete",
         "do", "double", "dynamic_cast", "else",
         "enum", "explicit", "export", "extern",
         "false", "float", "for", "friend",
         "goto", "if", "inline", "int",
         "long", "mutable", "namespace", "new",
         "noexcept", "not", "not_eq", "nullptr",
         "operator", "or", "or_eq", "private",
         "protected", "public", "register", "reinterpret_cast",
         "return", "short", "signed", "sizeof",
         "static", "static_assert", "static_cast", "struct",
         "switch", "template", "this", "thread_local",
         "throw", "true", "try", "typedef",
         "typeid", "typename", "union", "unsigned",
         "using", "virtual", "void", "volatile",
         "wchar_t", "while", "xor", "xor_eq",
         "pegtl" // this would not end well :)
      };
      // clang-format on

   }  // namespace

   template< typename Input >
   std::string get_rulename( const Input& in, data& d )
   {
      std::string v = in.string();
      std::replace( v.begin(), v.end(), '-', '_' );
      const auto it = d.find_rule( v );
      if( it != d.rules.rend() ) {
         return it->first;
      }
      if( keywords.count( v ) != 0 || v.find( "__" ) != std::string::npos ) {
         throw tao::TAOCPP_PEGTL_NAMESPACE::parse_error( "'" + in.string() + "' is a reserved rulename", in );
      }
      return v;
   }

   const std::size_t one_size = std::string( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< " ).size();

   namespace grammar = tao::TAOCPP_PEGTL_NAMESPACE::abnf::grammar;

   template< typename Rule >
   struct action
      : tao::TAOCPP_PEGTL_NAMESPACE::nothing< Rule >
   {
   };

   template<>
   struct action< grammar::push_stack >
   {
      static void apply0( data& d )
      {
         d.elements.emplace_back();
      }
   };

   template<>
   struct action< grammar::rulename >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         d.rulename = get_rulename( in, d );
      }
   };

   template<>
   struct action< grammar::rulename_val >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         std::string v = get_rulename( in, d );
         const auto it = d.find_rule( v );
         if( it == d.rules.rend() ) {
            d.rules.emplace_back( v, "" );
         }
         d.elements.back().push_back( v );
      }
   };

   template<>
   struct action< grammar::quoted_string >
   {
      static bool append( std::string& s, const char c )
      {
         if( !s.empty() ) {
            s += ", ";
         }
         s += '\'';
         if( c == '\'' || c == '\\' ) {
            s += '\\';
         }
         s += c;
         s += '\'';
         return std::isalpha( c ) != 0;
      }

      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         std::string s;
         bool alpha = append( s, in.peek_char( 1 ) );
         for( std::size_t pos = 2; pos < in.size() - 1; ++pos ) {
            alpha = append( s, in.peek_char( pos ) ) || alpha;
         }
         if( alpha ) {
            d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::istring< " + s + " >" );
         }
         else if( in.size() > 3 ) {
            d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::string< " + s + " >" );
         }
         else {
            d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< " + s + " >" );
         }
      }
   };

   template<>
   struct action< grammar::prose_val >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         const auto v = in.string();
         d.elements.back().push_back( "/* " + v.substr( 1, v.size() - 2 ) + " */" );
      }
   };

   template<>
   struct action< grammar::case_sensitive_string >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         if( d.elements.back().back()[ 7 ] == 'i' ) {
            d.elements.back().back().erase( 7, 1 );
         }
      }
   };

   template<>
   struct action< grammar::bin_val::value >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         const auto v = in.string();
         d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< " + std::to_string( std::strtoull( v.c_str(), nullptr, 2 ) ) + " >" );
      }
   };

   template<>
   struct action< grammar::bin_val::range >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         const auto end = d.elements.back().back();
         d.elements.back().pop_back();
         assert( !d.elements.back().empty() );
         const auto begin = d.elements.back().back();
         d.elements.back().back() = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::range< " + begin.substr( one_size, begin.size() - one_size - 2 ) + ", " + end.substr( one_size, end.size() - one_size - 2 ) + " >";
      }
   };

   template<>
   struct action< grammar::bin_val::next_value >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         const auto end = d.elements.back().back();
         d.elements.back().pop_back();
         assert( !d.elements.back().empty() );
         if( d.elements.back().back().substr( 0, one_size ) == "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< " ) {
            const auto begin = d.elements.back().back();
            d.elements.back().back() = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::string< " + begin.substr( one_size, begin.size() - one_size - 2 ) + ", " + end.substr( one_size, end.size() - one_size - 2 ) + " >";
         }
         else {
            d.elements.back().back().replace( d.elements.back().back().size() - 2, 2, ", " + end.substr( one_size ) );
         }
      }
   };

   template<>
   struct action< grammar::dec_val::value >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         const auto v = in.string();
         const auto p = v.find_first_not_of( '0' );
         d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< " + ( ( p == std::string::npos ) ? "0" : v.substr( p ) ) + " >" );
      }
   };

   template<>
   struct action< grammar::dec_val::range >
      : action< grammar::bin_val::range >
   {
   };

   template<>
   struct action< grammar::dec_val::next_value >
      : action< grammar::bin_val::next_value >
   {
   };

   template<>
   struct action< grammar::hex_val::value >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< 0x" + in.string() + " >" );
      }
   };

   template<>
   struct action< grammar::hex_val::range >
      : action< grammar::bin_val::range >
   {
   };

   template<>
   struct action< grammar::hex_val::next_value >
      : action< grammar::bin_val::next_value >
   {
   };

   template<>
   struct action< grammar::option >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         d.elements.back().back() = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::opt< " + d.elements.back().back() + " >";
      }
   };

   template<>
   struct action< grammar::repeat >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         d.elements.back().push_back( in.string() );
      }
   };

   template<>
   struct action< grammar::repetition >
   {
      static std::string remove_leading_zeroes( const std::string& v )
      {
         const auto pos = v.find_first_not_of( '0' );
         if( pos == std::string::npos ) {
            return "";
         }
         return v.substr( pos );
      }

      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         const auto size = d.elements.back().size();
         if( size > 1 ) {
            const auto value = d.elements.back()[ size - 2 ];
            if( value.find_first_not_of( "0123456789*" ) == std::string::npos ) {
               const auto element = d.elements.back().back();
               d.elements.back().pop_back();
               d.elements.back().pop_back();
               const auto star = value.find( '*' );
               if( star == std::string::npos ) {
                  const auto num = remove_leading_zeroes( value );
                  if( num.empty() ) {
                     throw tao::TAOCPP_PEGTL_NAMESPACE::parse_error( "repetition of zero not allowed", in );
                  }
                  d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::rep< " + num + ", " + element + " >" );
               }
               else {
                  const auto min = remove_leading_zeroes( value.substr( 0, star ) );
                  const auto max = remove_leading_zeroes( value.substr( star + 1 ) );
                  if( ( star != value.size() - 1 ) && max.empty() ) {
                     throw tao::TAOCPP_PEGTL_NAMESPACE::parse_error( "repetition maximum of zero not allowed", in );
                  }
                  if( min.empty() && max.empty() ) {
                     d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::star< " + element + " >" );
                  }
                  else if( !min.empty() && max.empty() ) {
                     if( min == "1" ) {
                        d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::plus< " + element + " >" );
                     }
                     else {
                        d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::rep_min< " + min + ", " + element + " >" );
                     }
                  }
                  else if( min.empty() && !max.empty() ) {
                     if( max == "1" ) {
                        d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::opt< " + element + " >" );
                     }
                     else {
                        d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::rep_opt< " + max + ", " + element + " >" );
                     }
                  }
                  else {
                     const auto min_val = std::strtoull( min.c_str(), nullptr, 10 );
                     const auto max_val = std::strtoull( max.c_str(), nullptr, 10 );
                     if( min_val > max_val ) {
                        throw tao::TAOCPP_PEGTL_NAMESPACE::parse_error( "repetition minimum which is greater than the repetition maximum not allowed", in );
                     }
                     const auto min_element = ( min_val == 1 ) ? element : "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::rep< " + min + ", " + element + " >";
                     if( min_val == max_val ) {
                        d.elements.back().push_back( min_element );
                     }
                     else if( max_val - min_val == 1 ) {
                        const auto max_element = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::opt< " + element + " >";
                        d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::seq< " + min_element + ", " + max_element + " >" );
                     }
                     else {
                        const auto max_element = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::rep_opt< " + std::to_string( max_val - min_val ) + ", " + element + " >";
                        d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::seq< " + min_element + ", " + max_element + " >" );
                     }
                  }
               }
            }
         }
      }
   };

   template<>
   struct action< grammar::and_predicate >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         d.elements.back().back() = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::at< " + d.elements.back().back() + " >";
      }
   };

   template<>
   struct action< grammar::not_predicate >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         assert( !d.elements.back().empty() );
         d.elements.back().back() = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::not_at< " + d.elements.back().back() + " >";
      }
   };

   template<>
   struct action< grammar::concatenation >
   {
      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         if( d.elements.back().size() == 1 ) {
            assert( d.elements.back().size() == 1 );
            const auto v = d.elements.back().back();
            d.elements.pop_back();
            assert( !d.elements.empty() );
            d.elements.back().push_back( v );
         }
         else {
            std::string s = d.elements.back().front();
            for( std::size_t p = 1; p != d.elements.back().size(); ++p ) {
               s += ", ";
               s += d.elements.back()[ p ];
            }
            d.elements.pop_back();
            assert( !d.elements.empty() );
            d.elements.back().push_back( "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::seq< " + s + " >" );
         }
      }
   };

   template<>
   struct action< grammar::alternation >
   {
      static bool is_one( const std::string& v )
      {
         return v.compare( 0, one_size, "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::one< " ) == 0;
      }

      static void apply0( data& d )
      {
         assert( !d.elements.empty() );
         if( d.elements.back().size() == 1 ) {
            assert( d.elements.back().size() == 1 );
            const auto v = d.elements.back().back();
            d.elements.pop_back();
            assert( !d.elements.empty() );
            d.elements.back().push_back( v );
         }
         else {
            std::string s = d.elements.back().front();
            bool one = is_one( s );
            for( std::size_t p = 1; p != d.elements.back().size(); ++p ) {
               const auto v = d.elements.back()[ p ];
               if( one && is_one( v ) ) {
                  s.replace( s.size() - 2, 2, ", " + v.substr( one_size ) );
               }
               else {
                  one = false;
                  s += ", ";
                  s += v;
               }
            }
            d.elements.pop_back();
            assert( !d.elements.empty() );
            if( !one ) {
               s = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::sor< " + s + " >";
            }
            d.elements.back().push_back( s );
         }
      }
   };

   template<>
   struct action< grammar::defined_as_op >
   {
      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         d.elements.back().push_back( in.string() );
      }
   };

   template<>
   struct action< grammar::rule >
   {
      static std::string strip_sor( const std::string& v )
      {
         return ( v.compare( 0, one_size, "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::sor< " ) == 0 ) ? v.substr( one_size, v.size() - one_size - 2 ) : v;
      }

      template< typename Input >
      static void apply( const Input& in, data& d )
      {
         assert( !d.elements.empty() );
         assert( d.elements.back().size() == 2 );
         auto value = d.elements.back().back();
         d.elements.back().pop_back();
         const auto op = d.elements.back().back();
         d.elements.back().pop_back();
         const auto it = d.find_rule( d.rulename );
         if( op == "=" ) {
            if( ( it != d.rules.rend() ) && !it->second.empty() ) {
               throw tao::TAOCPP_PEGTL_NAMESPACE::parse_error( "'" + d.rulename + "' has already been assigned", in );
            }
         }
         else {
            assert( op == "=/" );
            if( ( it == d.rules.rend() ) || it->second.empty() ) {
               throw tao::TAOCPP_PEGTL_NAMESPACE::parse_error( "'" + d.rulename + "' has not yet been assigned", in );
            }
            value = "tao::" TAOCPP_PEGTL_STRINGIFY( TAOCPP_PEGTL_NAMESPACE ) "::sor< " + strip_sor( it->second ) + ", " + strip_sor( value ) + " >";
            if( d.find_rule( d.rulename, std::next( it ) ) == d.rules.rend() ) {
               it->second.clear();
            }
            else {
               d.rules.erase( --it.base() );
            }
         }
         d.rules.emplace_back( d.rulename, value );
         d.elements.pop_back();
         assert( d.elements.empty() );
      }
   };

}  // namespace abnf2pegtl

int main( int argc, char** argv )
{
   using namespace tao::pegtl;

   if( argc != 2 ) {
      analyze< abnf::grammar::rulelist >();
      std::cerr << "Usage: " << argv[ 0 ] << " SOURCE" << std::endl;
      return 1;
   }

   abnf2pegtl::data d;
   file_input<> in( argv[ 1 ] );
   parse< abnf::grammar::rulelist, abnf2pegtl::action, abnf::grammar::error_control >( in, d );
   for( const auto& e : d.rules ) {
      if( e.second.empty() ) {
         if( !d.find_rule( e.first )->second.empty() ) {
            std::cout << "struct " << e.first << ";\n";
         }
      }
      else {
         std::cout << "struct " << e.first << " : " << e.second << " {};\n";
      }
   }
   return 0;
}
