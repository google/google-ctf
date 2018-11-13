#!/bin/bash

export a=`find . -maxdepth 1 -type f -name '*.c' | sort | sed -e 'sE\./EE' | sed -e 's/\.c/\.o/' | xargs`
perl ./parsenames.pl OBJECTS "$a"

# ref:         HEAD -> develop
# git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f
# commit time: 2018-09-23 21:37:58 +0200
