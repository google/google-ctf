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

import random
import logging


class GemNode:
    def __init__(self, name, nxt=None, value=0, shiny=False):
        self.name = name
        self.nxt = nxt
        self.value = value
        self.shiny = shiny  # Whether the gem is shiny or not
        self.weight = random.uniform(1, 10)  # Random weight for the gem
        self._secret = None  # Hidden attribute, potentially set later

    def count_gems_in_chain(self):
        # Function to count the number of gems from the current node onward
        count = 1
        current = self.nxt
        while current:
            count += 1
            current = current.nxt
        return count

    def set_secret_value(self, secret):
        self._secret = secret

    def get_secret_value(self):
        return self._secret

    def __repr__(self):
        return f"GemNode({self.name}, value={self.value}, shiny={self.shiny})"


cccc = GemNode("root", None)


class GemCollection:
    def __init__(self):
        try:
            self.purge()
        except Exception as e:
            pass
        self.root = cccc
        self.current_gem = self.root
        self.gems = [self.root]
        self.count_purges = 0
        self._ghost_gems = []

    def add_gem(self, new_gem):
        if self.current_gem is None:
            self.current_gem = new_gem
        else:
            self.current_gem.nxt = new_gem
            self.current_gem = new_gem
            self.gems.append(new_gem)
        # Randomly decide if this gem is shiny
        new_gem.shiny = random.choice([True, False])

    def purge(self):
        if random.choice([True, False]):
            logging.debug("Partial purge happened!")
            self._ghost_gems = self.gems[: random.randint(1, len(self.gems))]
        else:
            logging.debug("Full purge occurred!")
            self.root = None
            self.current_gem = None
            self.gems = []

    def count_all_gems(self):
        if not self.root:
            return 0
        cnt = 0
        # prevent cheating, make sure the gems are not just added somehow, like a blockchain
        current_gem = self.root
        while current_gem.nxt:
            cnt += 1
            current_gem = current_gem.nxt

        return cnt

    def count_shiny_gems(self):
        return len([gem for gem in self.gems if gem.shiny])

    def gem_ghost_resurrection(self):
        if self._ghost_gems:
            logging.debug(f"Resurrecting {len(self._ghost_gems)} ghost gems...")
            self.gems += self._ghost_gems
            self._ghost_gems = []

    def __repr__(self):
        return f"GemCollection(gems={len(self.gems)}, purged={self.count_purges})"


def new_gc():
    return GemCollection()
