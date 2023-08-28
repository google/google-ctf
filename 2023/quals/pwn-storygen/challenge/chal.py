# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import os

time.sleep(0.1)

print("Welcome to a story generator.")
print("Answer a few questions to get started.")
print()

name = input("What's your name?\n")
where = input("Where are you from?\n")

def sanitize(s):
  return s.replace("'", '').replace("\n", "")

name = sanitize(name)
where = sanitize(where)

STORY = """

#@NAME's story

NAME='@NAME'
WHERE='@WHERE'

echo "$NAME came from $WHERE. They always liked living there."
echo "They had 3 pets:"

types[0]="dog"
types[1]="cat"
types[2]="fish"

names[0]="Bella"
names[1]="Max"
names[2]="Luna"


for i in 1 2 3
do
  size1=${#types[@]}
  index1=$(($RANDOM % $size1))
  size2=${#names[@]}
  index2=$(($RANDOM % $size2))
  echo "- a ${types[$index1]} named ${names[$index2]}"
done

echo

echo "Well, I'm not a good writer, you can write the rest... Hope this is a good starting point!"
echo "If not, try running the script again."

"""


open("/tmp/script.sh", "w").write(STORY.replace("@NAME", name).replace("@WHERE", where).strip())
os.chmod("/tmp/script.sh", 0o777)

while True:
  s = input("Do you want to hear the personalized, procedurally-generated story?\n")
  if s.lower() != "yes":
    break
  print()
  print()
  os.system("/tmp/script.sh")
  print()
  print()

print("Bye!")
