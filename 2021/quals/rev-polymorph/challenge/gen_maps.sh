#!/bin/bash

ls public/malware | xargs -I{} -n1 echo /home/user/test_cases/{} 1 > expected_public_map
ls -p public/safe | grep -v / | xargs -I{} -n1 echo /home/user/test_cases/{} 0 >> expected_public_map

ls private/malware | xargs -I{} -n1 echo /home/user/test_cases/{} 1 > expected_map
ls private/safe | xargs -I{} -n1 echo /home/user/test_cases/{} 0 >> expected_map
