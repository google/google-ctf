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

import json
import logging
import os
import struct

from game.engine import hitbox
from game.components.items import check_item_loaded
from game.components.npc.npc import Npc

from game.engine import generics
from game.engine.keys import Keys


# This will specify a seed that is being used to generate the challenge.
# Should be refreshed every time the game gets reset. Maybe after each reset?
CHALLENGE_IDX_TO_LOAD = None
LOADED_CHALLENGE_IDX = None
CHALLENGE = None

def select_new_challenge():
    global CHALLENGE_IDX_TO_LOAD
    # Generate new random challenge ID that should be used.
    CHALLENGE_IDX_TO_LOAD = struct.unpack("<I", os.urandom(4))[0]
    logging.info(f"Selected {CHALLENGE_IDX_TO_LOAD} as challenge seed")

def assert_challenge_loaded():
    global CHALLENGE
    global CHALLENGE_IDX_TO_LOAD
    global LOADED_CHALLENGE_IDX

    if CHALLENGE_IDX_TO_LOAD is None:
        select_new_challenge()

    if LOADED_CHALLENGE_IDX == CHALLENGE_IDX_TO_LOAD:
        return

    challenge_idx = CHALLENGE_IDX_TO_LOAD

    generator = "dev/mimic.gen"
    challenge_file = f"/tmp/challenge{challenge_idx}.json"
    if os.path.exists(generator):
        if not os.path.exists(challenge_file):
            logging.info(f"Generating challenge seed={challenge_idx}")
            os.system(f"{generator} {challenge_idx} > {challenge_file}")
    else:
        logging.warning(f"Generator binary not found - build {generator} if you are hosting the server")

    if os.path.exists(challenge_file):
        try:
            with open(challenge_file, 'r') as f:
                CHALLENGE = json.loads(f.read())

            LOADED_CHALLENGE_IDX = challenge_idx
            return
        except:
            pass

    # Solution for the example:
    # xxxx
    # xxx.
    # .x.x
    # .x..
    logging.warning("Generating challenge failed, falling back to example challenge")
    with open('game/components/npc/example.json', 'r') as f:
        CHALLENGE = json.loads(f.read())
    CHALLENGE_IDX_TO_LOAD = "example"
    LOADED_CHALLENGE_IDX = "example"

def get_clue_text(npc_id):
    assert_challenge_loaded()

    return CHALLENGE['chests'][npc_id]['clue']

def is_mimic(npc_id):
    assert_challenge_loaded()

    return CHALLENGE['chests'][npc_id]['is_mimic']

class Chest(generics.GenericObject):
    open_chests = set()

    def __init__(self, coords, name, chest_id, **kwargs):
        tileset_path = "resources/objects/Chest.h8t"
        super().__init__(
            coords,
            nametype="Chest",
            tileset_path="resources/objects/Chest.h8t",
            name=name,
            blocking=True,
        )

        # Will be overwritten
        self.game = None

        scale = 1
        self.sprite.scale = scale
        w, h = self.sprite.get_dimensions()

        rect = hitbox.Rectangle(
            coords.x - w * scale / 2, coords.x + w * scale / 2,
            coords.y - h * scale / 2, coords.y + h * scale / 2,
        )
        self.update_hitbox(rect)
        self.sprite.set_animation("closed")

        self.id = int(chest_id)

        if kwargs:
            logging.warning(f"Unused arguments provided: {kwargs} for {name}")

    def tick(self):
        if (not self.game.player.dead and
                self.expand(20).collides(self.game.player)):
            if (Keys.E in self.game.newly_pressed_keys
                    and self.game.textbox is None):
                # Start a dialogue if we're close.
                self.dialogue()

        super().tick()

    def display_textbox(self, *args, **kwargs):
        self.game.display_textbox(*args, **kwargs)

    def dialogue_on_server(self):
        def resp_process(resp: str):
            if resp == "Open":
                if is_mimic(self.id):
                    Chest.open_chests.clear()
                    select_new_challenge()
                    self.game.display_textbox("Wrong", process_fun=self._wrong)
                else:
                    Chest.open_chests.add(self.id)
                    done = 4 * 4 - len(Chest.open_chests) == sum([1 if x['is_mimic'] else 0 for x in CHALLENGE['chests']])
                    extra = "" if not done else "\nI should speak to the NPC again"
                    self.game.display_textbox("Correct"+extra, process_fun=self._correct)
            else:
                self.game.display_textbox("Goodbye")
        if self.id in Chest.open_chests:
            self.display_textbox("This chest is already open")
            return

        self.display_textbox(get_clue_text(self.id), choices=["Open", "Better leave this one alone..."], process_fun=resp_process)

    def _correct(self, _v=None):
        self.sprite.set_animation("open")

    def _wrong(self, _v=None):
        self.game.player.dead = True
        for o in self.game.objects:
            if o.nametype == "Chest":
                o.sprite.set_animation("closed")

    def dialogue(self):
        if self.game.should_invoke_server_dialogue:
            self.dialogue_on_server()
        else:
            self.game.display_textbox(from_server=True, response_callbacks={"Correct": self._correct, "Wrong": self._wrong})

class ChestTrasher(Npc):
    def __init__(self, stars, **kwargs):
        item = None
        super().__init__(
            tileset_path="resources/NPCs/Trasher.h8t",
            scale=1,
            **kwargs,
        )
        coords = kwargs['coords']
        rect = rect = hitbox.Rectangle(coords.x - 20, coords.x + 20, coords.y - 30, coords.y + 35)
        self.stars = stars
        self.update_hitbox(rect)

    def dialogue(self):
        def get_stars(text):
            self.game.free_npc(self, self.stars)

        def dialogue_server():
            assert_challenge_loaded()
            chests_opened = len(Chest.open_chests)
            mimics_in_challenge = sum([1 if x['is_mimic'] else 0 for x in CHALLENGE['chests']])

            # If all chests have been opened
            if 4 * 4 - chests_opened == mimics_in_challenge:
                if LOADED_CHALLENGE_IDX != "example":
                    self.display_textbox("Wow, you did it!"+ f"\n\nDomino received *{self.stars}* stars!", process_fun=get_stars)
                else:
                    self.display_textbox("Wow, you did it! Now solve what you get from the server too")
            else:
                self.display_textbox(f"Please open all chests for me\nChests always speak the truth\nMimics always lie!\nThere are between {CHALLENGE['min_mimics']} and {CHALLENGE['max_mimics']} mimics out there, be careful!")

        if self.game.should_invoke_server_dialogue:
            dialogue_server()
        else:
            self.game.display_textbox(from_server=True, response_callbacks={"Wow, you did it!": get_stars})
