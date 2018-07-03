#!/bin/bash

# Copyright 2018 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Rounds of compression (MAX: 24)
ROUNDS=15

# Prepare initial ZIP
echo "CTF{CompressionIsNotEncryption}" > password.txt
zip -P asdf password.zip password.txt
rm password.txt
mv password.zip password.x

declare -a strings=(".a" ".b" ".c" ".d" ".e" ".f" ".g" ".h" ".i" ".j" ".k" ".l" ".m" ".n" ".o" ".p" ".q" ".r" ".s" ".t" ".u" ".v" ".w" ".x" ".y" ".z")

next=password.x

# Create the GZIP part
i=0
while [ $i -le $ROUNDS ]
do
  gzip < $next > "$next${strings[$i]}"
  rm -f $next
  next="$next${strings[$i]}"
  i=$[$i+1]
done

# Create the BZIP2 part
i=0
while [ $i -le $ROUNDS ]
do
  bzip2 $next
  mv "$next.bz2" "$next${strings[$i]}"
  next="$next${strings[$i]}"
  i=$[$i+1]
done

# Create the XZ part
i=$ROUNDS
while [ $i -ge 0 ]
do
  xz $next
  mv "$next.xz" "$next${strings[$i]}"
  next="$next${strings[$i]}"
  i=$[$i-1]
done

# Create the ZIP part
i=0
while [ $i -le $ROUNDS ]
do
  zip -m "$next.zip" $next
  mv "$next.zip" "$next${strings[$i]}"
  next="$next${strings[$i]}"
  i=$[$i+1]
done

