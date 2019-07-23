#!/usr/bin/python3

# Copyright 2019 Google LLC
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

import os
import subprocess
import sys

MOUNT_POINT = "/mnt/p3e"
FLAG_PATH = "Users/Family/Documents/credentials.txt"

if __name__ == "__main__":
  if len(sys.argv) < 3:
    print("Usage: sudo python3 {} <p3e.ntfs> <FILE0>".format(sys.argv[0]))
    sys.exit(1)

  disk_image = sys.argv[1]
  flag_attr = sys.argv[2]

  # Look at strings
  try:
    output = subprocess.check_output("strings {} | grep CTF".format(disk_image), shell=True)
    print("Error: Found CTF string in the disk image.")
    print(output)
    sys.exit(1)
  except subprocess.CalledProcessError:
    pass

  # Extract the PNG straight from the image
  f = open(disk_image, "rb")
  data = f.read()
  f.close()
  identifier = data.find(b"PNG") - 1
  if identifier < 0:
    print("Error: PNG header not found in the disk image.")
    sys.exit(1)

  f = open("test_{}_extracted.png".format(flag_attr), "wb")
  f.write(data[identifier:identifier + os.path.getsize("flag_{}.png".format(flag_attr))])
  f.close()

  # Mount the disk and retrieve images the intended way.
  os.makedirs(MOUNT_POINT, exist_ok=True)
  subprocess.call(["mount", "-t", "ntfs", "-o", "stream_interfaces=windows", disk_image, MOUNT_POINT])
  f = open("test_{}_intended.png".format(flag_attr), "wb")
  subprocess.call([
      "getfattr", "-n", "user.{}".format(flag_attr), "--only-values",
      os.path.join(MOUNT_POINT, FLAG_PATH)], stdout=f)
  f.close()
  subprocess.call(["umount", MOUNT_POINT])

  # Check SHA1 hashes
  subprocess.call("sha1sum *.png", shell=True)
