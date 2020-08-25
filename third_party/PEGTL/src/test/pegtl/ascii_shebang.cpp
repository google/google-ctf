// Copyright (c) 2014-2017 Dr. Colin Hirsch and Daniel Frey
// Please see LICENSE for license or visit https://github.com/taocpp/PEGTL/

#include "test.hpp"

namespace tao
{
   namespace TAOCPP_PEGTL_NAMESPACE
   {
      void unit_test()
      {
         verify_analyze< shebang >( __LINE__, __FILE__, true, false );

         verify_rule< shebang >( __LINE__, __FILE__, "", result_type::LOCAL_FAILURE, 0 );
         verify_rule< shebang >( __LINE__, __FILE__, "#", result_type::LOCAL_FAILURE, 1 );
         verify_rule< shebang >( __LINE__, __FILE__, "!", result_type::LOCAL_FAILURE, 1 );
         verify_rule< shebang >( __LINE__, __FILE__, "!#", result_type::LOCAL_FAILURE, 2 );
         verify_rule< shebang >( __LINE__, __FILE__, "#  ", result_type::LOCAL_FAILURE, 3 );
         verify_rule< shebang >( __LINE__, __FILE__, "!  ", result_type::LOCAL_FAILURE, 3 );
         verify_rule< shebang >( __LINE__, __FILE__, "## ", result_type::LOCAL_FAILURE, 3 );
         verify_rule< shebang >( __LINE__, __FILE__, "!! ", result_type::LOCAL_FAILURE, 3 );
         verify_rule< shebang >( __LINE__, __FILE__, "#!", result_type::SUCCESS, 0 );
         verify_rule< shebang >( __LINE__, __FILE__, "#! ", result_type::SUCCESS, 0 );
         verify_rule< shebang >( __LINE__, __FILE__, "#!/bin/bash", result_type::SUCCESS, 0 );
         verify_rule< shebang >( __LINE__, __FILE__, "#!/bin/bash\n", result_type::SUCCESS, 0 );
         verify_rule< shebang >( __LINE__, __FILE__, "#!/bin/bash\n#!/b", result_type::SUCCESS, 4 );
         verify_rule< shebang >( __LINE__, __FILE__, "#!\n", result_type::SUCCESS, 0 );
         verify_rule< shebang >( __LINE__, __FILE__, "#!\n ", result_type::SUCCESS, 1 );
      }

   }  // namespace TAOCPP_PEGTL_NAMESPACE

}  // namespace tao

#include "main.hpp"
