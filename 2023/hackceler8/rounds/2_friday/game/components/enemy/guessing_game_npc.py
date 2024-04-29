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

from .npc import Npc
from components import magic_items
from engine import hitbox
from engine.state import check_item_loaded

class GuessingGameNpc(Npc):
    solved = False

    def __init__(self, coords, name, walk_data):
        super().__init__(coords, name, walk_data, scale=1,
                         tileset_path="resources/NPCs/Duck_NPC.tmx")
        self.item = magic_items.Item(coords=None,
                                name="item_purple",
                                display_name="Purple key",
                                color="purple")
        outline = [
            hitbox.Point(coords.x - 36, coords.y - 31),
            hitbox.Point(coords.x + 36, coords.y - 31),
            hitbox.Point(coords.x + 36, coords.y + 37),
            hitbox.Point(coords.x - 36, coords.y + 37),
        ]
        self._update(outline)

    def dialogue(self):
        if not GuessingGameNpc.solved:
            if check_item_loaded(self.game.items, self.item):
                GuessingGameNpc.solved = True
        if GuessingGameNpc.solved:
            self.display_textbox("I don't have any more quacks to give you.\nGo quack somebody else.")
            return

        text = "Wanna play a game, quack?"
        def resp_process(resp : str):
            if resp == "YES":
                self._game()
            else:
                self.display_textbox("Shame, quack.")

        self.display_textbox(text, choices=["YES", "NO"], process_fun=resp_process)

    def _game(self):
        lo = 11
        hi = 14
        text = "Alright! It's a number guessing game.\nWhich number am I thinking of? It's between %d and %d" % (lo, hi)
        choices = [str(n) for n in range(lo, hi+1)]

        def resp_process(resp : str):
            num = "1337"
            if resp != num:
                self.display_textbox("I LIED! I was actually thinking of %s, quack." % num)
                return
            else:
                self.display_textbox(
                    "QUACK! How did you select that? Well I guess I'll have to give you a reward now.\n\n"
                    "Mew received *%s*!" % self.item.display_name)
                self.game.gather_items([self.item])
                GuessingGameNpc.solved = True

        self.display_textbox(text, choices=choices, process_fun=resp_process)
