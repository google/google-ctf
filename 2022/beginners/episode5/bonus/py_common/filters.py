# Copyright 2022 Google LLC
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
import time

BANNED_WORDS_FILE = "../common/wordlist.txt"
banned_words = []

def badlang_filter_load(force=False):
  if banned_words and not force:
    return

  with open(BANNED_WORDS_FILE) as f:
    for ln in f:
      ln = ln.strip().lower()
      if len(ln) < 5:
        print("warning: skipping bad words shorter than 5 characters")
        continue
      banned_words.append(ln)

def badlang_filter_check(text):
  text = text.lower().replace(" ", "").replace(".", "").replace("-", "").replace("_", "")
  for word in banned_words:
    if word in text:
      return False
  return True

def main():
  badlang_filter_load()
  assert(not badlang_filter_check("XYZTESTBADWORDTESTXYZ"))
  assert(not badlang_filter_check("X Y Z T E S T B A D W O R D  T  E S  T X Y Z"))
  assert(not badlang_filter_check("xyztestBADwordtestxyz"))

  assert(badlang_filter_check("this should be good"))
  print("Tests passed.")

if __name__=="__main__":
  main()
