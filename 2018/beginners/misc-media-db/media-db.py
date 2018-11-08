#!/usr/bin/env python2.7
#Copyright 2018 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import sqlite3
import random
import sys

BANNER = "=== Media DB ==="
MENU = """\
1) add song
2) play artist
3) play song
4) shuffle artist
5) exit"""

with open('oauth_token') as fd:
  flag = fd.read()

conn = sqlite3.connect(':memory:')
c = conn.cursor()

c.execute("CREATE TABLE oauth_tokens (oauth_token text)")
c.execute("CREATE TABLE media (artist text, song text)")
c.execute("INSERT INTO oauth_tokens VALUES ('{}')".format(flag))

def my_print(s):
  sys.stdout.write(s + '\n')
  sys.stdout.flush()

def print_playlist(query):
  my_print("")
  my_print("== new playlist ==")
  for i, res in enumerate(c.execute(query).fetchall()):
    my_print('{}: "{}" by "{}"'.format(i+1, res[1], res[0]))
  my_print("")

my_print(BANNER)

while True:
  my_print(MENU)
  sys.stdout.write("> ")
  sys.stdout.flush()
  choice = raw_input()
  if choice not in ['1', '2', '3', '4', '5']:
    my_print('invalid input')
    continue
  if choice == '1':
    my_print("artist name?")
    artist = raw_input().replace('"', "")
    my_print("song name?")
    song = raw_input().replace('"', "")
    c.execute("""INSERT INTO media VALUES ("{}", "{}")""".format(artist, song))
  elif choice == '2':
    my_print("artist name?")
    artist = raw_input().replace("'", "")
    print_playlist("SELECT artist, song FROM media WHERE artist = '{}'".format(artist))
  elif choice == '3':
    my_print("song name?")
    song = raw_input().replace("'", "")
    print_playlist("SELECT artist, song FROM media WHERE song = '{}'".format(song))
  elif choice == '4':
    artist = random.choice(list(c.execute("SELECT DISTINCT artist FROM media")))[0]
    my_print("choosing songs from random artist: {}".format(artist))
    print_playlist("SELECT artist, song FROM media WHERE artist = '{}'".format(artist))
  else:
    my_print("bye")
    exit(0)
