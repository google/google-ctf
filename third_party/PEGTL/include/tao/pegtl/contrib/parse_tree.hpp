// Copyright (c) 2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_CONTRIB_PARSE_TREE_HPP
#define TAOCPP_PEGTL_INCLUDE_CONTRIB_PARSE_TREE_HPP

#include <memory>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include "../config.hpp"
#include "../normal.hpp"

#include "../internal/iterator.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      namespace parse_tree
      {
         struct node
         {
            std::vector< std::unique_ptr< node > > children;
            const std::type_info* id = nullptr;
            internal::iterator begin;
            internal::iterator end;
			virtual ~node() {}
         };

         class state
         {
         private:
            std::vector< std::unique_ptr< node > > stack;

         public:
            state()
            {
               emplace_back();
            }

            const node& root() const noexcept
            {
               return *stack.front();
            }

            std::unique_ptr< node >& back() noexcept
            {
               return stack.back();
            }

            void pop_back() noexcept
            {
               return stack.pop_back();
            }

            void emplace_back()
            {
               stack.emplace_back( std::unique_ptr< node >( new node ) );
            }
         };

      }  // namespace parse_tree

      namespace internal
      {
         template< template< typename > class S, template< typename > class C >
         struct parse_tree
         {
            template< typename Rule, bool = S< Rule >::value, bool = C< Rule >::value >
            struct builder;
         };

         template< template< typename > class S, template< typename > class C >
         template< typename Rule >
         struct parse_tree< S, C >::builder< Rule, false, false >
            : normal< Rule >
         {
         };

         template< template< typename > class S, template< typename > class C >
         template< typename Rule >
         struct parse_tree< S, C >::builder< Rule, true, true >
            : normal< Rule >
         {
            static_assert( sizeof( Rule ) == 0, "error: both S<Rule>::value and C<Rule>::value are true" );
         };

         template< template< typename > class S, template< typename > class C >
         template< typename Rule >
         struct parse_tree< S, C >::builder< Rule, true, false >
            : normal< Rule >
         {
            template< typename Input >
            static void start( const Input& in, TAOCPP_PEGTL_NAMESPACE::parse_tree::state& s )
            {
               s.emplace_back();
               s.back()->begin = in.iterator();
			   s.back()->id = &typeid(Rule);
            }

            template< typename Input >
            static void success( const Input&, TAOCPP_PEGTL_NAMESPACE::parse_tree::state& s )
            {
               auto n = std::move( s.back() );
               s.pop_back();
               s.back()->children.emplace_back( std::move( n ) );
            }

            template< typename Input >
            static void failure( const Input&, TAOCPP_PEGTL_NAMESPACE::parse_tree::state& s )
            {
               s.pop_back();
            }
         };

         template< template< typename > class S, template< typename > class C >
         template< typename Rule >
         struct parse_tree< S, C >::builder< Rule, false, true >
            : normal< Rule >
         {
            template< typename Input >
            static void start( const Input& in, TAOCPP_PEGTL_NAMESPACE::parse_tree::state& s )
            {
               s.emplace_back();
               s.back()->begin = in.iterator();
			   s.back()->id = &typeid(Rule);
            }

            template< typename Input >
            static void success( const Input& in, TAOCPP_PEGTL_NAMESPACE::parse_tree::state& s )
            {
               auto n = std::move( s.back() );
               n->end = in.iterator();
               s.pop_back();
               s.back()->children.emplace_back( std::move( n ) );
            }

            template< typename Input >
            static void failure( const Input&, TAOCPP_PEGTL_NAMESPACE::parse_tree::state& s )
            {
               s.pop_back();
            }
         };

         template< typename >
         struct default_store_simple : std::false_type
         {
         };

         template< typename >
         struct default_store_content : std::true_type
         {
         };

      }  // namespace internal

      namespace parse_tree
      {
         template< typename Rule >
         struct builder
            : internal::parse_tree< internal::default_store_simple, internal::default_store_content >::builder< Rule >
         {
         };

         template< template< typename > class S, template< typename > class C >
         struct make_builder
         {
            template< typename Rule >
            struct type
               : internal::parse_tree< S, C >::template builder< Rule >
            {
            };
         };

      }  // namespace parse_tree

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
