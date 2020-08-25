// Copyright (c) 2016-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#ifndef TAOCPP_PEGTL_INCLUDE_EOL_HPP
#define TAOCPP_PEGTL_INCLUDE_EOL_HPP

#include <cstddef>
#include <utility>

#include "config.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      using eol_pair = std::pair< bool, std::size_t >;

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "internal/cr_crlf_eol.hpp"
#include "internal/cr_eol.hpp"
#include "internal/crlf_eol.hpp"
#include "internal/lf_crlf_eol.hpp"
#include "internal/lf_eol.hpp"

#include "internal/eol.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      inline namespace ascii
      {
         // this is both a rule and a pseudo-namespace for eol::cr, ...
         struct eol : internal::eol
         {
            // clang-format off
            struct cr : internal::cr_eol {};
            struct cr_crlf : internal::cr_crlf_eol {};
            struct crlf : internal::crlf_eol {};
            struct lf : internal::lf_eol {};
            struct lf_crlf : internal::lf_crlf_eol {};
            // clang-format on
         };

      }  // namespace ascii

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#endif
