#!/usr/bin/python3 -u

# Copyright 2022 Google LLC
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

import os
import os.path
import subprocess
import urllib.parse


_BASE_DIR = "/tmp/"
_REPO_DIR = None

_BANNER = """
 _       ____ _ _
 | | ___ / ___(_) |_
 | |/ _ \ |  _| | __|
 | |  __/ |_| | | |_
 |_|\___|\____|_|\__|

"""


def menu():
  print("Welcome! How can I help you?")
  print("1- List files in repository")
  print("2- Show file in repository")
  print("3- Check for updates")
  print("4- Pull updates")
  print("5- Exit")
  try:
    return int(input(">>> "))
  except:
    return -1


def encode_repo_url(repo_url):
  return urllib.parse.quote(repo_url, safe='').replace('.', '%2e')


def build_repo_dir(repo_url):
  return os.path.join(_BASE_DIR, encode_repo_url(repo_url))


def clone_repo():
  global _REPO_DIR
  repo_url = input(">>> Repo url: ")
  repo_url = repo_url.strip()
  _REPO_DIR = build_repo_dir(repo_url)
  result = subprocess.run(["git", "clone", "--end-of-options", repo_url,
                           _REPO_DIR],
                          capture_output=True)
  if result.returncode != 0:
    print("Error while cloning repo")
    exit(1)
  print("Repo cloned!")
  os.chdir(_REPO_DIR)


def list_files():
  dirpath = "."
  while True:
    real_dirpath = os.path.realpath(os.path.join(_REPO_DIR, dirpath))
    if _REPO_DIR != os.path.commonpath((_REPO_DIR, real_dirpath)):
      print("Hacker detected!")
      return
    try:
      os.chdir(real_dirpath)
    except:
      print("Invalid directory.")
      return
    result = subprocess.run(["ls"], capture_output=True)
    if result.returncode != 0:
      print("Error while listing files.")
      return
    print(result.stdout.decode())
    print("Would you like to explore a subdirectory?")
    subdir = input(">>> [cwd={}] Subdirectory to enter: ".format(dirpath))
    subdir = subdir.strip()
    if not subdir:
      return
    dirpath = os.path.normpath(os.path.join(dirpath, subdir))


def show_file():
  filepath = input(">>> Path of the file to display: ")
  real_filepath = os.path.realpath(os.path.join(_REPO_DIR, filepath))
  if _REPO_DIR != os.path.commonpath((_REPO_DIR, real_filepath)):
    print("Hacker detected!")
    return
  result = subprocess.run(["cat", real_filepath], capture_output=True)
  if result.returncode != 0:
    print("Error while retrieving file content.")
    return
  print(result.stdout.decode())


def check_updates():
  result = subprocess.run(["git", "fetch"], capture_output=True)
  if not result.stdout:
    print("Nothing new...")
    return
  print("The repository has new data! Fetched :)")


def pull_updates():
  # TODO: Implement this.
  pass


if __name__ == '__main__':
  print(_BANNER)
  clone_repo()
  while True:
    option = menu()

    if option == 1:
      list_files()
    elif option == 2:
      show_file()
    elif option == 3:
      check_updates()
    elif option == 4:
      pull_updates()
    elif option == 5:
      print("kthxbye")
      break
    else:
      print("Invalid option :(")
