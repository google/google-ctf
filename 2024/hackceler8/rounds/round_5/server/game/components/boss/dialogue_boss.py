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

from random import Random, randint
from os import urandom
from game.components.boss.boss import Boss
from game.engine import hitbox


class DialogueBoss(Boss):

    def __init__(self, coords):
        super().__init__(coords, name="dialogue_boss", tileset_path="resources/villain/snake_lady.h8t")
        self.name = "dialogue_boss"
        rect = hitbox.Rectangle(coords.x - 60, coords.x + 60, coords.y - 90, coords.y + 90)
        self.update_hitbox(rect)
        # TODO BEFORE RELEASING TO PLAYERS: Remove block start
        self.rnd = Random(urandom(32))
        # TODO BEFORE RELEASING TO PLAYERS: Remove block end


    def _chat(self):
        if self.game.is_server or self.game.net is None:
            self.secret_server_dialogue()
        else:
            self.game.display_textbox(from_server=True, response_callbacks={"Imposssssible, that's correct": self._start_destruct})

    def secret_server_dialogue(self):
        # TODO BEFORE RELEASING TO PLAYERS: Remove block start
        def guess(resp: str):
            try:
                guess = [int(i.strip()) for i in resp.split(",")]
            except:
                self.game.display_textbox("Invalid format")
                return
            if guess == self.nums:
                self.game.display_textbox("Imposssssible, that's correct!\n", process_fun=self._start_destruct)
            else:
                txt = "Incorrect! I was thinking of the following:\n"
                txt += ", ".join([str(i) for i in self.nums])
                self.game.display_textbox(txt)

        def choose_count(resp: str):
            try:
                num = int(resp)
            except:
                self.game.display_textbox("That'sssss not a number, don't trick me!")
                return
            if num <= 0:
                self.game.display_textbox("Positive numbers plssss")
                return
            if num < 10:
                self.game.display_textbox("Too small! That wouldn't be a challenge now would it?")
                return
            if num > 1000:
                self.game.display_textbox("That'ssssss a bit too large don't you think?")
                return
            self.num_count = num
            self.nums = [self.rnd.randint(0, self.max_num) for i in range(self.num_count)]
            txt = "Alright then, I thought of %d numbers between 0 and %d, what are they? Comma-separated values pls." % (self.num_count, self.max_num)
            self.game.display_textbox(txt, free_text=True, process_fun=guess)

        def choose_max(resp: str):
            try:
                num = int(resp)
            except:
                self.game.display_textbox("That'sssss not a number, don't trick me!")
                return
            if num <= 0:
                self.game.display_textbox("Positive numbers plssss")
                return
            if num < 100:
                self.game.display_textbox("Too small! That wouldn't be a challenge now would it?")
                return
            if num > 10000000000:
                self.game.display_textbox("That'ssssss a bit too large don't you think?")
                return
            self.max_num = num
            self.game.display_textbox("And how many numberssss do you want to guess?", free_text=True, process_fun=choose_count)

        def maybe_guess(resp: str):
            if resp == "Challenge accepted!":
                txt = "I'm feeling generoussssss so I'll let you choose the largessst number to use. What should it be?"
                self.game.display_textbox(txt, free_text=True, process_fun=choose_max)
            else:
                self.game.display_textbox("Farewell")

        self.game.display_textbox("Greetingssss, mortal!\nYou shall not passss unless you can guess the numberssss I'm thinking of.", choices=["Challenge accepted!", "Okay, bye"], process_fun=maybe_guess)
        return
        # TODO BEFORE RELEASING TO PLAYERS: Remove block end
        self.game.display_textbox("Boss battle only available on the sssserver.")

    def _start_destruct(self, text):
        text = "I've been defeated! Victory is yours young canine."
        self.sprite.set_animation("die")
        self.game.display_textbox(text, process_fun=self.destruct)

    def tick(self):
        super().tick()
        if self.destructing or self.dead:
            return
        self.sprite.set_flipped(self.game.player.x < self.x)
