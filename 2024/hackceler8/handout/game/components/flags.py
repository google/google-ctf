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

import logging
import struct
import time
import os
import json
from pathlib import Path
from game.map.tileset import read_str


class Flag:
    def __init__(self, name, stars):
        self.name = name
        self.stars = stars
        self.collected_time = 0


class Flags:
    def __init__(self, flags, stars_for_boss):
        self.flags = flags
        self.stars_for_boss = stars_for_boss

    def obtained(self, name):
        for f in self.flags:
            if f.name == name:
                return f.collected_time > 0
        return False

    def unlocked_boss(self):
        return self.stars() >= self.stars_for_boss

    def beat_bosses(self):
        found_beaten = False
        found_unbeaten = False
        for f in self.flags:
            if f.name.endswith("_boss"):
                if f.collected_time > 0:
                    found_beaten = True
                else:
                    found_unbeaten = True
        return found_beaten and not found_unbeaten

    def last_boss(self):
        total = 0
        beat = 0
        for f in self.flags:
            if f.name.endswith("_boss"):
                if f.collected_time > 0:
                    beat += 1
                total += 1
        return total == beat + 1

    def obtain_flag(self, name, coll_time=time.time()):
        for f in self.flags:
            if f.name == name:
                if f.collected_time == 0:
                    f.collected_time = coll_time
                return
        logging.error(f"Couldn't find flag {name} in list")

    def stars(self):
        total = 0
        for f in self.flags:
            if f.collected_time > 0:
                total += f.stars
        return total

    def dump(self):
        return [{"name": f.name, "stars": f.stars, "collected_time": f.collected_time} for f in self.flags]


# Load the flags for this match based on the NPCs and bosses present on the maps.
def load_match_flags():
    stars_for_boss = 100000
    flags = []
    for path in ["resources/levels", "resources/maps"]:
        for root, dirs, files in os.walk(path, topdown=True):
            for f in files:
                if not f.endswith(".h8m"):
                    continue
                with open(Path(os.path.join(root, f)), "rb") as mf:
                    # Skip to objects.
                    mf.seek(8, 0)
                    for i in range(struct.unpack("<H", mf.read(2))[0]):
                        _ = read_str(mf)
                        mf.seek(2, 1)
                    for i in range(struct.unpack("<H", mf.read(2))[0]):
                        _ = read_str(mf)
                        h = struct.unpack("<H", mf.read(2))[0]
                        w = struct.unpack("<H", mf.read(2))[0]
                        mf.seek(1, 1)
                        mf.seek(2 * h * w, 1)
                    for i in range(struct.unpack("<H", mf.read(2))[0]):
                        name = stars = stars_needed = None
                        for j in range(struct.unpack("<H", mf.read(2))[0]):
                            key = read_str(mf)
                            match mf.read(1):
                                case b'\x00':
                                    val = read_str(mf)
                                case b'\x01':
                                    val = struct.unpack("?", mf.read(1))[0]
                                case b'\x02':
                                    val = struct.unpack("<i", mf.read(4))[0]
                                case b'\x03':
                                    val = struct.unpack("<f", mf.read(4))[0]
                                case _:
                                    logging.error(f"Invalid val type")
                                    return None
                            if key == "name":
                                name = val
                            elif key == "stars":
                                stars = val
                            elif key == "stars_needed":
                                stars_needed = val
                        # Freeable NPCs
                        if name.startswith("trapped_") and name.endswith("_npc"):
                            flags.append(Flag(name.removeprefix("trapped_").removesuffix("_npc"), stars))
                        # Bosses
                        if name.endswith("_boss_gate"):
                            name = name
                            flags.append(Flag(name.removesuffix("_gate"), 9999))
                            stars_for_boss = min(stars_for_boss, stars_needed)
    return Flags(flags, stars_for_boss)
