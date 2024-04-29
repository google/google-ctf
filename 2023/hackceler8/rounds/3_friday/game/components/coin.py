# Copyright 2023 Google LLC
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
import constants

from engine import generics
from engine.state import check_item_loaded
from components import magic_items

class Coin(generics.GenericObject):
    def __init__(self, coords, name, decay_time):
        super().__init__(coords, "Coin", "resources/objects/coin.tmx", None, name)

        self.decay_time_seconds = decay_time

        self.decay_time = self.decay_time_seconds * (constants.TICK_S ** -1)
        self.remaining_time = self.decay_time
        self.blocking = False
        self.collected = False
        self.decayed = False

    def tick(self):
        self.remaining_time -= 1
        if self.remaining_time < 1:
            logging.debug(f"Time is up for coin {self.name}")
            self.decayed = True

    def reset(self):
        self.remaining_time = self.decay_time
        self.decayed = False
        self.collected = False
        logging.debug(f"Reset loading time for coin {self.name} at"
                     f" {self.remaining_time}")


class CoinCollection:
    def __init__(self, game):
        self.coins = []
        self.item = magic_items.Item(coords=None,
                                     name="key_violet",
                                     display_name="Violet key",
                                     color="violet")
        self.solved = check_item_loaded(game.items, self.item)

    def add(self, it):
        self.coins.append(it)

    def check(self):
        if self.solved:
            return False
        self.solved = all([i.collected for i in self.coins])
        if self.solved:
            self.coins = []
        return self.solved
