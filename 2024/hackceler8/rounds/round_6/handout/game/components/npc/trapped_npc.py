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

from game.engine import hitbox
from game.components.npc.npc import Npc
from interpreter import punchcard
from interpreter.encodings import rototo


class TrappedNpc(Npc):

    def __init__(self, tileset_path, text, stars, requires_password=False, is_correct_fun=None, **kwargs):
        solved = {}
        super().__init__(
            scale=1,
            tileset_path=tileset_path,
            **kwargs,
        )
        self.text = text
        self.stars = stars
        self.requires_password = requires_password
        if self.requires_password and not is_correct_fun:
            raise Exception("Can't initiate trapped PW NPC without a check function")

    def dialogue(self):
        if not self.requires_password:
            self.simple_get_stars()
        else:
            self.solve_riddle()

    def solve_riddle(self):
        text = "Yo Dawg, you got something for me?"

        def resp_process(resp: str):
            if resp == "Bet":
                self.display_textbox(
                    "Then hit me up G",
                    free_text=True,
                    process_fun=password_check,
                )
            else:
                self.display_textbox("Too bad, come back any time my G.")

        def password_check(password: str):
            if self.is_correct_fun(password):
                answer = (
                    "That's deadass right! !\n\nDomino "
                    "received *%s*!"
                )
                self.simple_get_stars()
                return
            else:
                self.display_textbox("Nah dawg, you trippin', better try again.")

        self.display_textbox(text, choices=["Bet", "Cap"], process_fun=resp_process)

    def simple_get_stars(self):
        def get_stars(text):
            self.game.free_npc(self, self.stars)

        star_str = "star" if self.stars == 1 else "stars"
        self.display_textbox(self.text + f"\n\nDomino received *{self.stars}* {star_str}!", process_fun=get_stars)


class Quackington(TrappedNpc):
    @staticmethod
    def is_correct_fun(pw):
        pcr = punchcard.PunchCardReader(raw=pw)
        pcr.run()
        return rototo(pcr.program).startswith('JFWI(QR_SXQFKF4UG_1QW3QG3G_38H7I)')

    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Quackington.h8t",
            "Thanks for freeing me, quack!",
            **kwargs,
        )
        self.requires_password = True
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 36, coords.x + 36, coords.y - 31, coords.y + 37)
        self.update_hitbox(rect)


class Jessse(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Jessse.h8t",
            "Thanksssss for releassssing me!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 15, coords.x + 15, coords.y - 25, coords.y + 25)
        self.update_hitbox(rect)


class Trasher(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Trasher.h8t",
            "Thanks for freeing me!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 20, coords.x + 20, coords.y - 30, coords.y + 35)
        self.update_hitbox(rect)


class Casher(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Casher.h8t",
            "Thanks fer freein' me jimbo!",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 20, coords.x + 20, coords.y - 30, coords.y + 35)
        self.update_hitbox(rect)


class Raibbit(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Raibbit.png",
            "* BEEEP *\nGRATITUDE PROTOCOLS ACTIVATED\nTHANK YOU FOR YOUR ASSISTANCE IN FREEING ME",
            **kwargs,
        )
        coords = kwargs['coords']
        rect = hitbox.Rectangle(coords.x - 80, coords.x + 80, coords.y - 93, coords.y + 80)
        self.update_hitbox(rect)
        self.sprite.scale = 0.7
        self.render_above_player = True


class HungryTrasher(Trasher):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hunger = 0
        self.dead = False
        self.full = False
        self.activated = False

    def tick(self):
        super().tick()
        if not self.activated:
            if self.expand(10000).collides(self.game.player):
                self.activated = True
            else:
                return

        if self.full:
            return
        self.hunger += 1
        if self.hunger == 10000:  # 10k ticks is a little under 3 minutes
            self.die()
        else:
            if not (self.hunger % 1000) and self.expand(10000).collides(self.game.player):
                self.display_textbox("MOMMA I'M HUNGRYYYYYYYYYYYYY")

    def die(self):
        if self.expand(20).collides(self.game.player):
            self.display_textbox("You failed to feed me in time and now I'm gone to an upstate farm. I hope you're proud of yourself", process_fun=self.killah)

    def killah(self, resp=""):
        self.game.kill_npc(self)

    def dialogue(self):
        self.basic_interaction()

    def basic_interaction(self, resp=""):
        self.display_textbox("You got some crops?",
                             choices=["bet, no cap", "cap", "idk"],
                             process_fun=self.switcher)

    def gib_crops(self, resp=""):
        def get_stars_dom(text):
            self.game.free_npc(self, self.stars)

        for it in self.game.stateful_inventory:
            if it.name == "crops":
                if it.growth_level < 8:
                    self.display_textbox("Those crops are too small, this is Texas...")
                    return
                star_str = "star" if self.stars == 1 else "stars"
                self.full = True
                self.display_textbox("I like the chops of your crops" + f"\n\nDomino received *{self.stars}* {star_str}!", process_fun=get_stars_dom)
                return
        self.display_textbox("No crops no props.")

    def switcher(self, resp):
        match resp:
            case "bet, no cap":
                self.gib_crops("")
            case _:
                self.display_textbox("I'm always looking to eat ya feel me")
