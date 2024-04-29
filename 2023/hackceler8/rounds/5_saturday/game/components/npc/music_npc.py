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

from .npc import Npc
from engine import hitbox
from engine.state import check_item_loaded
from components import magic_items
from components.jam_session import JamSession


class MusicNpc(Npc):
    solved = {}

    def __init__(self, id, verify_callback, end_callback, item, tileset_path, coords,
                 name, walk_data):
        super().__init__(coords, name, walk_data, scale=1,
                         tileset_path=tileset_path)
        self.id = id
        self.verify_callback = verify_callback
        self.end_callback = end_callback
        self.item = item
        outline = [
            hitbox.Point(coords.x - 15, coords.y - 25),
            hitbox.Point(coords.x + 15, coords.y - 25),
            hitbox.Point(coords.x + 15, coords.y + 25),
            hitbox.Point(coords.x - 15, coords.y + 25),
        ]
        self._update(outline)

    def dialogue(self):
        if not MusicNpc.solved.get(self.id, False):
            if check_item_loaded(self.game.items, self.item):
                MusicNpc.solved[self.id] = True
        if MusicNpc.solved.get(self.id, False):
            self.display_textbox(
                "Thanks again, your song changed my life!")
            return

        text = "Show Me What You Got"

        def resp_process(resp: str):
            if resp == "Ok":
                self.display_textbox(text, process_fun=self._done_cb)
            else:
                self.display_textbox("I'll be waiting")

        self.display_textbox(text, choices=["Ok", "Maybe Later"],
                             process_fun=resp_process)

    def _done_cb(self, _foo):
        self.game.jam_session = JamSession(
            game = self.game,
            verify_callback=self.verify_callback,
            end_callback=self.end_callback
        )


class RaccoonMusicNpc(MusicNpc):
    def __init__(self, coords, name, walk_data):
        item = magic_items.Item(
            coords=None,
            name="key_violet",
            display_name="Violet key",
            color="violet",
        )
        super().__init__("Song_Npc", self._verify_callback, self._end_callback, item,
                         "resources/NPCs/Racoon_NPC.tmx",
                         coords, name, walk_data)

    @staticmethod
    def generate_challenge():
        # For elise
        T = 5
        return [
            (19, T), (18, T), (19, T), (18, T), (19, T), (14, T), (17, T), (15, T),
            (12, 2 * T), (None, T),
            (3, T), (7, T), (12, T), (14, 2 * T), (None, T),

            (7, T), (11, T), (14, T), (15, T), (None, T),

            (7, T),
            (19, T), (18, T), (19, T), (18, T), (19, T), (14, T), (17, T), (15, T),
            (12, 2 * T), (None, T),
            (3, T), (7, T), (12, T), (14, 2 * T), (None, T),

            (5, T), (15, T), (14, T), (12, 4 * T),
        ]

    def _verify_callback(self, seq):
        challenge = RaccoonMusicNpc.generate_challenge()
        seq = seq[-len(challenge):]

        if len(seq) != len(challenge):
            return False

        if seq == challenge:
            if self.item is not None:
                self.game.gather_items([self.item])
            MusicNpc.solved[self.id] = True
            return True
        else:
            return False

    def _end_callback(self, was_successful):
        if was_successful:
            self.display_textbox(
                f"That was amazing, have a little something\n\nMew received *{self.item.display_name}*")
        else:
            self.display_textbox("At least you tried")
