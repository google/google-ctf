// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include <type_traits>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/alphabet.hpp>

namespace test
{
   // We only need to test that this compiles...

   struct foo : TAOCPP_PEGTL_STRING( "foo" )
   {
   };

   struct foobar : tao::TAOCPP_PEGTL_NAMESPACE::sor< TAOCPP_PEGTL_STRING( "foo" ), TAOCPP_PEGTL_STRING( "bar" ) >
   {
   };

   static_assert( std::is_same< TAOCPP_PEGTL_STRING( "Hello" ), tao::TAOCPP_PEGTL_NAMESPACE::string< 'H', 'e', 'l', 'l', 'o' > >::value, "TAOCPP_PEGTL_STRING broken" );
   static_assert( !std::is_same< TAOCPP_PEGTL_ISTRING( "Hello" ), tao::TAOCPP_PEGTL_NAMESPACE::string< 'H', 'e', 'l', 'l', 'o' > >::value, "TAOCPP_PEGTL_ISTRING broken" );
   static_assert( std::is_same< TAOCPP_PEGTL_ISTRING( "Hello" ), tao::TAOCPP_PEGTL_NAMESPACE::istring< 'H', 'e', 'l', 'l', 'o' > >::value, "TAOCPP_PEGTL_ISTRING broken" );

   static_assert( std::is_same< TAOCPP_PEGTL_KEYWORD( "private" ), tao::TAOCPP_PEGTL_NAMESPACE::keyword< 'p', 'r', 'i', 'v', 'a', 't', 'e' > >::value, "TAOCPP_PEGTL_KEYWORD broken" );

   // Strings may even contain embedded nulls

   static_assert( std::is_same< TAOCPP_PEGTL_STRING( "Hello, w\0rld!" ), tao::TAOCPP_PEGTL_NAMESPACE::string< 'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 0, 'r', 'l', 'd', '!' > >::value, "TAOCPP_PEGTL_STRING broken" );

   // The strings currently have a maximum length of 512 characters.

   using namespace tao::TAOCPP_PEGTL_NAMESPACE::alphabet;
   static_assert( std::is_same< TAOCPP_PEGTL_STRING( "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz" ),
                                tao::TAOCPP_PEGTL_NAMESPACE::string< a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z > >::value,
                  "TAOCPP_PEGTL_STRING broken" );

}  // namespace test

int main()
{
   return 0;
}
