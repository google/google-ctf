// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_CONTRIB_RAW_STRING_HPP
#define TAOCPP_PEGTL_INCLUDE_CONTRIB_RAW_STRING_HPP

#include "../apply_mode.hpp"
#include "../config.hpp"
#include "../nothing.hpp"
#include "../rewind_mode.hpp"

#include "../internal/iterator.hpp"
#include "../internal/must.hpp"
#include "../internal/skip_control.hpp"
#include "../internal/state.hpp"
#include "../internal/until.hpp"

#include "../analysis/generic.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace internal
      {
         template< char Open, char Marker, char Close, typename... Contents >
         struct raw_string_tag;

         template< bool use_apply_void, bool use_apply0_void, typename Tag >
         struct raw_string_state_apply;

         template< typename Tag >
         struct raw_string_state_apply< false, false, Tag >
         {
            template< template< typename... > class,
                      template< typename... > class,
                      typename State,
                      typename Input,
                      typename... States >
            static void success( const State&, const Input&, States&&... )
            {
            }
         };

         template< typename Tag >
         struct raw_string_state_apply< true, false, Tag >
         {
            template< template< typename... > class Action,
                      template< typename... > class Control,
                      typename State,
                      typename Input,
                      typename... States >
            static void success( const State& s, const Input& in, States&&... st )
            {
               Control< Tag >::template apply< Action >( s.iter, in, st... );
            }
         };

         template< typename Tag >
         struct raw_string_state_apply< false, true, Tag >
         {
            template< template< typename... > class Action,
                      template< typename... > class Control,
                      typename State,
                      typename Input,
                      typename... States >
            static void success( const State&, const Input& in, States&&... st )
            {
               Control< Tag >::template apply0< Action >( in, st... );
            }
         };

         template< typename Tag, typename Iterator >
         struct raw_string_state
         {
            template< typename Input, typename... States >
            raw_string_state( const Input&, States&&... )
            {
            }

            template< apply_mode A,
                      rewind_mode,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename... States >
            void success( Input& in, States&&... st ) const
            {
               constexpr char use_action = ( A == apply_mode::ACTION ) && ( !is_nothing< Action, Tag >::value );
               constexpr char use_apply_void = use_action && internal::has_apply< Action< Tag >, void, typename Input::action_t, States... >::value;
               constexpr char use_apply_bool = use_action && internal::has_apply< Action< Tag >, bool, typename Input::action_t, States... >::value;
               constexpr char use_apply0_void = use_action && internal::has_apply0< Action< Tag >, void, States... >::value;
               constexpr char use_apply0_bool = use_action && internal::has_apply0< Action< Tag >, bool, States... >::value;
               static_assert( use_apply_void + use_apply_bool + use_apply0_void + use_apply0_bool < 2, "more than one apply or apply0 defined" );
               static_assert( !use_action || use_apply_bool || use_apply_void || use_apply0_bool || use_apply0_void, "actions not disabled but no apply or apply0 found" );
               static_assert( use_apply_bool + use_apply0_bool == 0, "actions with bool result not supported in raw_string" );
               raw_string_state_apply< use_apply_void, use_apply0_void, Tag >::template success< Action, Control >( *this, in, st... );
               in.bump_in_this_line( marker_size );
            }

            raw_string_state( const raw_string_state& ) = delete;
            void operator=( const raw_string_state& ) = delete;

            Iterator iter;
            std::size_t marker_size = 0;
         };

         template< char Open, char Marker >
         struct raw_string_open
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< apply_mode A,
                      rewind_mode,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename State >
            static bool match( Input& in, State& ls )
            {
               if( in.empty() || ( in.peek_char( 0 ) != Open ) ) {
                  return false;
               }
               for( std::size_t i = 1; i < in.size( i + 1 ); ++i ) {
                  switch( const auto c = in.peek_char( i ) ) {
                     case Open:
                        ls.marker_size = i + 1;
                        in.bump( ls.marker_size );
                        eol::match( in );
                        ls.iter = in.iterator();
                        return true;
                     case Marker:
                        break;
                     default:
                        return false;
                  }
               }
               return false;
            }
         };

         template< char Open, char Marker >
         struct skip_control< raw_string_open< Open, Marker > > : std::true_type
         {
         };

         template< char Marker, char Close >
         struct at_raw_string_close
         {
            using analyze_t = analysis::generic< analysis::rule_type::ANY >;

            template< apply_mode A,
                      rewind_mode,
                      template< typename... > class Action,
                      template< typename... > class Control,
                      typename Input,
                      typename State >
            static bool match( Input& in, const State& ls )
            {
               if( in.size( ls.marker_size ) < ls.marker_size ) {
                  return false;
               }
               if( in.peek_char( 0 ) != Close ) {
                  return false;
               }
               if( in.peek_char( ls.marker_size - 1 ) != Close ) {
                  return false;
               }
               for( std::size_t i = 0; i < ls.marker_size - 2; ++i ) {
                  if( in.peek_char( i + 1 ) != Marker ) {
                     return false;
                  }
               }
               return true;
            }
         };

         template< char Marker, char Close >
         struct skip_control< at_raw_string_close< Marker, Close > > : std::true_type
         {
         };

      }  // namespace internal

      // raw_string matches Lua-style long literals.
      //
      // The following description was taken from the Lua documentation
      // (see http://www.lua.org/docs.html):
      //
      // - An "opening long bracket of level n" is defined as an opening square
      //   bracket followed by n equal signs followed by another opening square
      //   bracket. So, an opening long bracket of level 0 is written as `[[`,
      //   an opening long bracket of level 1 is written as `[=[`, and so on.
      // - A "closing long bracket" is defined similarly; for instance, a closing
      //   long bracket of level 4 is written as `]====]`.
      // - A "long literal" starts with an opening long bracket of any level and
      //   ends at the first closing long bracket of the same level. It can
      //   contain any text except a closing bracket of the same level.
      // - Literals in this bracketed form can run for several lines, do not
      //   interpret any escape sequences, and ignore long brackets of any other
      //   level.
      // - For convenience, when the opening long bracket is immediately followed
      //   by a newline, the newline is not included in the string.
      //
      // Note that unlike Lua's long literal, a raw_string is customizable to use
      // other characters than `[`, `=` and `]` for matching. Also note that Lua
      // introduced newline-specific replacements in Lua 5.2, which we do not
      // support on the grammar level.

      template< char Open, char Marker, char Close, typename... Contents >
      struct raw_string
      {
         // This is used as a tag to bind an action to the content.
         using content = internal::raw_string_tag< Open, Marker, Close, Contents... >;

         // This is used internally.
         using open = internal::raw_string_open< Open, Marker >;

         // This is used for error-reporting when a raw string is not closed properly.
         using close = internal::until< internal::at_raw_string_close< Marker, Close >, Contents... >;

         using analyze_t = analysis::generic< analysis::rule_type::SEQ, open, internal::must< close > >;

         template< apply_mode A,
                   rewind_mode M,
                   template< typename... > class Action,
                   template< typename... > class Control,
                   typename Input,
                   typename... States >
         static bool match( Input& in, States&&... st )
         {
            using Iterator = typename Input::iterator_t;
            internal::raw_string_state< content, Iterator > s( const_cast< const Input& >( in ), st... );

            if( Control< internal::seq< open, internal::must< close > > >::template match< A, M, Action, Control >( in, s ) ) {
               s.template success< A, M, Action, Control >( in, st... );
               return true;
            }
            return false;
         }
      };

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
