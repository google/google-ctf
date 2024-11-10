# Copyright 2024 Google LLC
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

# Script for applying redactions to the code before releasing for a round.
# Note that this might not redact new round-specific things, make sure to go
# Through the files manually before releasing.
# Assumed to be run from the game/dev/ directory

import os
import subprocess
import generate_maps

files_to_rm = [
    "Makefile",
    "poc",
    "cheat",
    "binaries/src",
    "binaries/Makefile",
    "resources/development",
    "game/engine/arcade_system/nsjail",
    "game/engine/arcade_system/chroot",
    "game/components/boss/implementation_server.py",
]

lines_to_rm = {
    "README.md": [
        (
            "4. Run challenge's PoC script\n```\ncd "
            "hackceler8-2024-game\nsource ../my_venv/bin/activate\n# export "
            "all_proxy=http://localhost:3128\npython3 -m"
            " poc.poc_example\n```\n"
        ),
        (
            "If you want to run the server without it auto-generating\nas "
            "an additional argument\n\nYou can also regenerate the binaries with\n"
        ),
    ],
}

replacements = {
    "fighting_boss.py": {"game.components.boss.implementation_server": "game.components.boss.implementation"},
}


def remove_files():
  for f in files_to_rm:
    p = subprocess.run(["rm", "-rf", "../" + f])
    if p.returncode != 0:
      print(f"rm -rf ../{f} returned an error")
      exit(1)

def redact_file(path):
  to_rm = lines_to_rm.get(path.split("/")[-1], [])
  with open(path, "r") as f:
    content = f.read().split("\n")
  changed = False

  # Remove manually specified stuff
  for rm in to_rm:
    rm_lines = rm.split("\n")
    for i in range(len(content)):
      if rm_lines[0] in content[i]:
        content = content[:i] + content[i + len(rm_lines) :]
        changed = True
        break

  # Remove blocks instructed by comments
  while True:
    start = None
    end = None
    for i in range(len(content)):
      if "# TODO BEFORE RELEASING TO PLAYERS" in content[i].upper():
        if "remove block start" in content[i].lower():
          if start is not None:
            print(
                f"Error redacting {path}: Mismatched TODO block at line {i + 1}"
            )
            exit(1)
          start = i
        if "remove block end" in content[i].lower():
          if start is None:
            print(
                f"Error redacting {path}: Mismatched TODO block at line {i + 1}"
            )
            exit(1)
          end = i
          content = content[:start] + content[end + 1 :]
          changed = True
          break
    if start is None:  # Done removing all
      break

  new_content = "\n".join(content).strip() + "\n"
  # Replace stuff from replacement list
  for f, rs in replacements.items():
    if f in path:
      for old, new in rs.items():
        new_content = new_content.replace(old, new)
        changed = True

  if not changed:
    return

  with open(path, "w") as f:
    f.write(new_content)

def remove_tiled_maps():
  for root, dirs, files in os.walk("../resources", topdown=True):
    for f in files:
      if f.endswith(".tsx") or f.endswith(".tmx"):
        os.remove(os.path.join(root, f))

if __name__ == "__main__":
  remove_files()
  for root, dirs, files in os.walk("..", topdown=True):
    for f in files:
      if f == "redact_for_release.py":  # Skip self
        continue
      if f.endswith(".py") or f.endswith(".md"):
        redact_file(root + "/" + f)
  # Create custom maps and remove the Tiled ones
  generate_maps.generate("../resources")
  remove_tiled_maps()
  # Last step: Remove parent dir * Insert Skeletor breaking mirror meme *
  subprocess.run(["rm", "-rf", "../dev"])
