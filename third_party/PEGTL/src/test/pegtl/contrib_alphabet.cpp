// Copyright (c) 2015-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/contrib/alphabet.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         static_assert( alphabet::a == 'a', "a" );
         static_assert( alphabet::b == 'b', "b" );
         static_assert( alphabet::c == 'c', "c" );
         static_assert( alphabet::d == 'd', "d" );
         static_assert( alphabet::e == 'e', "e" );
         static_assert( alphabet::f == 'f', "f" );
         static_assert( alphabet::g == 'g', "g" );
         static_assert( alphabet::h == 'h', "h" );
         static_assert( alphabet::i == 'i', "i" );
         static_assert( alphabet::j == 'j', "j" );
         static_assert( alphabet::k == 'k', "k" );
         static_assert( alphabet::l == 'l', "l" );
         static_assert( alphabet::m == 'm', "m" );
         static_assert( alphabet::n == 'n', "n" );
         static_assert( alphabet::o == 'o', "o" );
         static_assert( alphabet::p == 'p', "p" );
         static_assert( alphabet::q == 'q', "q" );
         static_assert( alphabet::r == 'r', "r" );
         static_assert( alphabet::s == 's', "s" );
         static_assert( alphabet::t == 't', "t" );
         static_assert( alphabet::u == 'u', "u" );
         static_assert( alphabet::v == 'v', "v" );
         static_assert( alphabet::w == 'w', "w" );
         static_assert( alphabet::x == 'x', "x" );
         static_assert( alphabet::y == 'y', "y" );
         static_assert( alphabet::z == 'z', "z" );

         static_assert( alphabet::A == 'A', "A" );
         static_assert( alphabet::B == 'B', "B" );
         static_assert( alphabet::C == 'C', "C" );
         static_assert( alphabet::D == 'D', "D" );
         static_assert( alphabet::E == 'E', "E" );
         static_assert( alphabet::F == 'F', "F" );
         static_assert( alphabet::G == 'G', "G" );
         static_assert( alphabet::H == 'H', "H" );
         static_assert( alphabet::I == 'I', "I" );
         static_assert( alphabet::J == 'J', "J" );
         static_assert( alphabet::K == 'K', "K" );
         static_assert( alphabet::L == 'L', "L" );
         static_assert( alphabet::M == 'M', "M" );
         static_assert( alphabet::N == 'N', "N" );
         static_assert( alphabet::O == 'O', "O" );
         static_assert( alphabet::P == 'P', "P" );
         static_assert( alphabet::Q == 'Q', "Q" );
         static_assert( alphabet::R == 'R', "R" );
         static_assert( alphabet::S == 'S', "S" );
         static_assert( alphabet::T == 'T', "T" );
         static_assert( alphabet::U == 'U', "U" );
         static_assert( alphabet::V == 'V', "V" );
         static_assert( alphabet::W == 'W', "W" );
         static_assert( alphabet::X == 'X', "X" );
         static_assert( alphabet::Y == 'Y', "Y" );
         static_assert( alphabet::Z == 'Z', "Z" );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
