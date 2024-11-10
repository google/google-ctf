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
from game.engine.shop import Shop, ShopItem
import logging


class TrappedNpc(Npc):

    def __init__(self, tileset_path, text, stars, **kwargs):
        super().__init__(
            scale=1,
            tileset_path=tileset_path,
            **kwargs,
        )
        self.text = text
        self.stars = stars

    def dialogue(self):
        def get_stars(text):
            self.game.free_npc(self, self.stars)

        star_str = "star" if self.stars == 1 else "stars"
        self.display_textbox(self.text + f"\n\nDomino received *{self.stars}* {star_str}!", process_fun=get_stars)


class Quackington(TrappedNpc):
    def __init__(self, **kwargs):
        item = None
        super().__init__(
            "resources/NPCs/Quackington.h8t",
            "Thanks for freeing me, quack!",
            **kwargs,
        )
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

        self.shop = Shop(
            items=[
                ShopItem("Cookie", 0.1, True),
                ShopItem("Stars", 101),
            ],
            initial_cash=100
        )

        self.text = ""
        self.update_text()
        self.current_items_in_cart = 0
        self.item_name_in_cart = ""

    def winwin(self):
        def get_stars(text):
            self.game.free_npc(self, self.stars)

        star_str = "star" if self.stars == 1 else "stars"
        self.display_textbox(f"\n\nDomino received *{self.stars}* {star_str}!", process_fun=get_stars)

    def dialogue(self):
        self.basic_interaction(None)

    def update_text(self):
        self.text = f"Do you want to buy some stuff? You currently have " \
                    f"{self.shop.current_cash} DominoSDs"

    def reset_cart(self):
        self.current_items_in_cart = 0
        self.item_name_in_cart = ""

    def process_buying(self, resp: str):
        items_in_transaction = 0
        try:
            items_in_transaction = int(resp)
        except Exception as e:
            self.display_textbox(f"No H4ck3rs please",
                                 process_fun=self.basic_interaction)
            return
        if items_in_transaction != 0:
            item_name = self.item_name_in_cart.split(':')[0]
            bought_success = self.shop.buy_bulk(item_name, items_in_transaction)
            self.update_text()
            self.reset_cart()
            if bought_success:
                if item_name == "Stars":
                    self.winwin()
                self.display_textbox(f"Nice, you now have {items_in_transaction} {item_name}",
                                     process_fun=self.basic_interaction)
            else:
                self.display_textbox(f"Hmmm living a bit above our means there jimbo, "
                                     f"you only have {int(self.shop.current_cash)} DominoSDs, "
                                     f"you need an additional "
                                     f"{int(self.shop.items[item_name].value - self.shop.current_cash)}",
                                     process_fun=self.basic_interaction)

    def process_selling(self, resp: str):
        try:
            items_in_transaction = int(resp)
        except Exception as e:
            logging.critical(e)
            self.display_textbox(f"No H4ck3rs please",
                                 process_fun=self.basic_interaction)
            return
        if items_in_transaction != 0:
            item_name = self.item_name_in_cart.split(':')[0]
            sold_success = self.shop.sell_bulk(item_name, items_in_transaction)
            self.update_text()
            if sold_success:
                self.display_textbox(
                    f"Nice, you sold {items_in_transaction} {item_name} and now have {int(self.shop.current_cash)} DominoSDs",
                    process_fun=self.basic_interaction)
            else:
                self.display_textbox(f"You either don't have that item or it's not "
                                     f"sellable jimbo, ya trying to trick me?",
                                     process_fun=self.basic_interaction)

    def process_inventory(self, resp: str):
        have_now = f"Current DominoSDs: {int(self.shop.current_cash)}"
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
                if self.shop.player_inventory_total == 0:
                    self.display_textbox("You don't have any items!",
                                         process_fun=self.basic_interaction)
                else:
                    self.selling("")
            case "Inventory":
                self.process_inventory("")
            case _:  # Quit
                self.display_textbox("If ya need some good stuff ya know where to find me")

    def shopping(self, resp):
        if self.shop.current_cash == 0:
            self.display_textbox("Sorry jimbo, looks like you're out of money")
        self.display_textbox("Whatcha buyin' today?",
                             choices=[f"{i}: {self.shop.items[i].value}" for i in
                                      self.shop.items],
                             process_fun=self.shopping_bulk)

    def shopping_bulk(self, resp):
        self.item_name_in_cart = resp
        self.display_textbox("How many d'ya want?", free_text=True, process_fun=self.process_buying)

    def selling(self, resp):
        self.display_textbox("Sure thing, I'll be glad to buy some stuff back from ya",
                             choices=[f"{i}: {self.shop.items[i].value}" for i in
                                      self.shop.player_inventory if
                                      self.shop.player_inventory[i] > 0],
                             process_fun=self.selling_bulk)

    def selling_bulk(self, resp):
        self.item_name_in_cart = resp
        self.display_textbox("How many ya looking to move?", free_text=True, process_fun=self.process_selling)

    def basic_interaction(self, resp):
        self.display_textbox("You buyin' or sellin'? You can also check your inventory",
                             choices=["Buying", "Selling", "Inventory", "I'm good thanks"],
                             process_fun=self.switcher)


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
