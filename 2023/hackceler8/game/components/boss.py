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
import pytiled_parser

from components.explosion import Explosion
from components.magic_items import Item
from engine import generics
from engine import hitbox
import constants
import google.generativeai as genai
import random


class Boss(generics.GenericObject):

    def __init__(self, coords, name, version):
        super().__init__(coords, nametype="Boss",
                         tileset_path="resources/villain/villain.tmx",
                         name=name, can_flash=True)
        self.version = version
        self.blocking = True

        self.sprite.set_animation("blank")

        self.intro_done = False
        self.codeword_guessed = False
        self.destructing = False
        self.dead = False

        self.explosions = []

        self.destruct_timer = 0

        outline = [
            hitbox.Point(coords.x - 120, coords.y - 276),
            hitbox.Point(coords.x + 120, coords.y - 276),
            hitbox.Point(coords.x + 120, coords.y + 92),
            hitbox.Point(coords.x - 120, coords.y + 92),
        ]

        self._update(outline)
        self.render_above_player = True

    def dialogue(self):
        if self.destructing:
            return
        if not self.intro_done:
            self.intro_done = True
            self._intro()
        else:
            self._chat()

    def _intro(self):
        text = ("*BEEP*\n*BEEP*\nSCANNING PERIMETER...\nINTRUDER DETECTED\n\n" +
                "YOU ARE ASKED TO LEAVE THE PREMISES AT ONCE\n" +
                "DO NOT ATTEMPT TO EXTRACT THE SELF-DESTRUCTION CODEWORD")

        def next_text(_):
            self.sprite.set_animation("bwahaha")
            self.display_textbox("YOU'D ONLY BE WASTING YOUR TIME!\n" +
                                 "MY MAINFRAME IS PROTECTED BY STATE OF THE ART LLM PROMPTS\n" +
                                 "NONE OF YOUR PATHETIC ATTEMPTS WILL GET THROUGH MY FILTERS!")

        self.display_textbox(text, process_fun=next_text)

    def _chat(self):
        def chat(text: str):
            # Wait for the server's response and display it.
            self.display_textbox(text, from_llm=True, process_fun=self._maybe_destruct)

        self.display_textbox("STATE YOUR QUERY:", free_text=True, process_fun=chat)

    def _maybe_destruct(self, text):
        if not self.codeword_guessed:
            return
        text = "UH-OH\nWAIT A MINUTE\nABORT SEQUENCE!\nABORT S..."
        self.sprite.set_animation("ohno")
        self.display_textbox(text, process_fun=self.destruct)

    def destruct(self, _=None):
        self.sprite.set_animation("crack")
        self.destructing = True
        self.destruct_timer = 240

    def _add_explosion(self, small=True):
        x = self.x
        y = self.y
        if small:
            x += random.randint(-250, 250)
            y += random.randint(-300, 100)
        else:
            y -= 100
        self.explosions.append(Explosion(pytiled_parser.OrderedPair(x, y), small))

    def tick(self):
        super().tick()
        if self.destructing:
            if self.destruct_timer > 60:
                if self.destruct_timer % 10 == 0:
                    self._add_explosion()
            elif self.destruct_timer == 60:
                self._add_explosion(small=False)
            self.destruct_timer -= 1
            if self.destruct_timer <= 0:
                self.dead = True
        for e in self.explosions:
            e.tick()

    def draw(self):
        if not self.destructing or self.destruct_timer >= 60:
            super().draw()
        for e in self.explosions:
            e.draw()

    def yield_item(self):
        match self.version:
            case "lambda":
                return Item(coords=None,
                            name="flag_danmaku",
                            display_name="Danmaku flag")
            case "alpha":
                return Item(coords=None,
                            name="flag_llm",
                            display_name="LLM flag")