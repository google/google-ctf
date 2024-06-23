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
from engine import hitbox
from engine.shop import Shop, ShopItem

import logging


class BankerNPC(Npc):
    solved = {}

    def __init__(self, coords, name, walk_data):
        super().__init__(coords, name, walk_data, scale=1,
                         tileset_path="resources/NPCs/Fancy_Racoon_NPC.tmx")
        self.id = id
        # self.is_correct_fun = is_correct_fun
        self.shop = Shop(
            items=[
                ShopItem("Cookie", 1, True),
                ShopItem("Badge", 100),
                ShopItem("Flag", 100000),
            ],
            initial_cash=100
        )
        outline = [
            hitbox.Point(coords.x - 15, coords.y - 25),
            hitbox.Point(coords.x + 15, coords.y - 25),
            hitbox.Point(coords.x + 15, coords.y + 25),
            hitbox.Point(coords.x - 15, coords.y + 25),
        ]
        self._update(outline)
        self.text = ""
        self.update_text()

    def update_text(self):
        self.text = f"Do you want to buy some stuff? You currently have " \
                    f"{self.shop.current_cash} MewSDs"

    def dialogue(self):
        self.basic_interaction(None)

    def process_buying(self, resp: str):
        item_name = resp.split(':')[0]
        bought_success = self.shop.buy(item_name)
        self.update_text()
        if bought_success:
            self.display_textbox(f"Nice, you now have one {item_name}",
                                 process_fun=self.basic_interaction)
        else:
            self.display_textbox(f"Hmmm living a bit above our means there jimbo, "
                                 f"you only have {self.shop.current_cash} MewSDs, "
                                 f"you need an additional "
                                 f"{self.shop.items[item_name].value - self.shop.current_cash}",
                                 process_fun=self.basic_interaction)

    def process_selling(self, resp: str):
        item_name = resp.split(':')[0]
        sold_success = self.shop.sell(item_name)
        self.update_text()
        if sold_success:
            self.display_textbox(
                f"Nice, you sold one {item_name} and now have {self.shop.current_cash} MewSDs",
                process_fun=self.basic_interaction)
        else:
            self.display_textbox(f"You either don't have that item or it's not "
                                 f"sellable jimbo, ya trying to trick me?",
                                 process_fun=self.basic_interaction)

    def process_inventory(self, resp: str):
        have_now = f"Current MewSDs: {self.shop.current_cash}"
        itms = False
        for i in self.shop.player_inventory:
            if self.shop.player_inventory[i] > 0:
                have_now += f"\n{i} ({self.shop.player_inventory[i]})" \
                        f"{'(SELLABLE)' if self.shop.items[i].sellable else ''}"
                itms = True

        if not itms:
            have_now += "\n\nYa don't have any items jimbo, gotta spend money to make " \
                        "money, 'nam saying'?"

        self.display_textbox(have_now,
                             process_fun=self.basic_interaction)

    def switcher(self, resp):
        match resp:
            case "Buying":
                self.shopping("")
            case "Selling":
                if self.shop.player_inventory_total != 0:
                    self.selling("")
                self.display_textbox("You don't have any items!",
                                     process_fun=self.basic_interaction)
            case "Inventory":
                self.process_inventory("")
            case _: # Quit
                self.display_textbox("If ya need some good stuff ya know where to find me")

    def shopping(self, resp):
        if self.shop.current_cash == 0:
            self.display_textbox("Sorry jimbo, looks like you're out of money")
        logging.info(f"Resp given: {resp}")
        self.display_textbox("Whatcha buyin' today?",
                             choices=[f"{i}: {self.shop.items[i].value}" for i in
                                      self.shop.items],
                             process_fun=self.process_buying)

    def selling(self, resp):
        self.display_textbox("Sure thing, I'll be glad to buy some stuff back from ya",
                             choices=[f"{i}: {self.shop.items[i].value}" for i in
                                      self.shop.player_inventory if
                                      self.shop.player_inventory[i] > 0],
                             process_fun=self.process_selling)

    def basic_interaction(self, resp):
        self.display_textbox("You buyin' or sellin'? You can also check your inventory",
                             choices=["Buying", "Selling", "Inventory", "I'm good thanks"],
                             process_fun=self.switcher)
