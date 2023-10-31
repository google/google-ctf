#Copyright 2020 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#!/usr/bin/env python2.7
import subprocess
import sys
import time
from threading import Timer

def main():
  server = sys.stdin.readline()
  server = server.strip()

  server_len = 0
  while server_len < min(128,len(server)) and (server[server_len] == '/' or server[server_len] == '.' or server[server_len] == ':' or server[server_len].isalnum()):
    server_len += 1
  server = server[:server_len]

  if not server.startswith("http://") and not server.startswith("https://"):
      print("incorrect url")
      exit(0)

  print("connecting to {}".format(server))

  argv = [
      "./chrome/chrome",
      "--user-data-dir=/tmp/chrometmp",
      "--enable-blink-features=MojoJS",
      "--disable-gpu",
      server
  ]
  env = {
      'DISPLAY': ':100'
  }

  proc = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  time.sleep(10)
  print("timeout")
  proc.kill()

if __name__ == '__main__':
  main()
