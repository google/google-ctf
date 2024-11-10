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

from game.engine import generics
from game.engine import hitbox
from game.engine.keys import Keys
from game.components import items


class ATMReward:

    def __init__(self):
        self.winning_text = ""
        self.item = None
        self.game = None
        self.name = "atm"

    def win(self):
        if self.item and not self.game.has_item(self.item.name):
            self.game.gather_item(self.item)


class Kudos(ATMReward):
    def __init__(self):
        super().__init__()
        self.winning_text = "Kudos for winning!"


class Keyz(ATMReward):
    def __init__(self):
        super().__init__()
        self.winning_text = "You got gud item."
        self.item = items.Item(coords=None, name="key", display_name="Key")


class PeerBonus(ATMReward):
    def __init__(self):
        super().__init__()
        self.winning_text = "Kudos for winning!"


REWARDS = {
    "key": Keyz(),
    "kudos": Kudos(),
    "peer_bonus": PeerBonus()
}


class ATM(generics.GenericObject):
    def __init__(self, coords, reward_type, gems_needed):
        super().__init__(
            coords=coords,
            name="atm",
            nametype="atm",
            tileset_path="resources/objects/atm.png",
            can_flip=True,
            blocking=True,
        )
        self.sprite.set_flipped(True)
        w, h = self.sprite.get_dimensions()
        rect = hitbox.Rectangle(
            coords.x - w * 0.5, coords.x + w * 0.5,
            coords.y - h * 0.5, coords.y + h * 0.5,
        )
        self.update_hitbox(rect)
        self.reward_type = reward_type
        self.reward_function = REWARDS[self.reward_type]
        self.gems_needed = gems_needed

        self.game = None

    def tick(self):
        if self.game.gem_collection:
            self.interact()
        super().tick()

    def display_textbox(self, *args, **kwargs):
        self.game.display_textbox(*args, **kwargs)

    def interact(self):
        if (not self.game.player.dead and
                self.expand(20).collides(self.game.player)):
            if Keys.E in self.game.newly_pressed_keys:
                logging.info(f"Player has {self.game.gem_collection.count_all_gems()} gems")
                if self.game.gem_collection.count_all_gems() >= self.gems_needed:
                    logging.info("Player can collect the reward!")
                    self.reward_function.win()
                    self.display_textbox(
                        self.reward_function.winning_text
                    )
                else:
                    self.display_textbox(
                        f"Stop being poor! You need another {self.gems_needed - self.game.gem_collection.count_all_gems()} gems to collect the reward."
                    )
                    logging.info(f"Player has {self.game.gem_collection.count_all_gems()} gems but needs {self.gems_needed} to unlock the reward")
