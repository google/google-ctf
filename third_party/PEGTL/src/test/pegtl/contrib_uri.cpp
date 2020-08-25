// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

#include <tao/pegtl/contrib/uri.hpp>

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      using GRAMMAR = must< uri::URI, eof >;

      void unit_test()
      {
         verify_analyze< GRAMMAR >( __LINE__, __FILE__, true, false );

         verify_rule< GRAMMAR >( __LINE__, __FILE__, "http://de.wikipedia.org/wiki/Uniform_Resource_Identifier", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "ftp://ftp.is.co.za/rfc/rfc1808.txt", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "file:///C:/Users/Benutzer/Desktop/Uniform%20Resource%20Identifier.html", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "file:///etc/fstab", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "geo:48.33,14.122;u=22.5", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "ldap://[2001:db8::7]/c=GB?objectClass?one", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "gopher://gopher.floodgap.com", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "mailto:John.Doe@example.com", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "sip:911@pbx.mycompany.com", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "news:comp.infosystems.www.servers.unix", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "data:text/plain;charset=iso-8859-7,%be%fa%be", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "tel:+1-816-555-1212", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "telnet://192.0.2.16:80/", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "urn:oasis:names:specification:docbook:dtd:xml:4.1.2", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "git://github.com/rails/rails.git", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "crid://broadcaster.com/movies/BestActionMovieEver", result_type::SUCCESS, 0 );
         verify_rule< GRAMMAR >( __LINE__, __FILE__, "http://nobody:password@example.org:8080/cgi-bin/script.php?action=submit&pageid=86392001#section_2", result_type::SUCCESS, 0 );

         verify_fail< GRAMMAR >( __LINE__, __FILE__, "" );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
