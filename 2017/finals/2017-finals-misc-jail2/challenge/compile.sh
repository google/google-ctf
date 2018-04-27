#!/bin/bash -eu
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



#!/bin/bash
tfile=$(mktemp /tmp/foo.XXXXXXXXX)

echo "How many lines do you want to compile?"
read line_count


re='^[0-9]+$'
if ! [[ $line_count =~ $re ]] ; then
   echo "$line_count is not a number :("; exit 1
fi

echo "Reading source... $line_count"
while read -r line; do
    echo -E $line >> $tfile
    ((line_count -= 1))
    if [[ line_count -eq 0 ]]; then
  		break
	fi
done <&0


gcc -o /tmp/bin.o -x c $tfile 
echo "Executing..."
exec /tmp/bin.o
exit 99
