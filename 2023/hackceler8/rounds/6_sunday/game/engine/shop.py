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
from collections import defaultdict


class ShopItem:
    def __init__(self, name, value, sellable=False):
        self.name = name
        self.value = value
        self.sellable = sellable


class Shop:
    def __init__(self, items: list[ShopItem], initial_cash: int):
        self.items = {}
        self.initial_cash = initial_cash

        self.current_cash = initial_cash
        self.player_inventory_total = 0

        self.generate_shop(items)

        self.player_inventory = defaultdict(int)

    def update_inventory_count(self):
        tmp = 0
        for i in self.player_inventory:
            tmp += self.player_inventory[i]
        self.player_inventory_total = tmp

    def buy(self, item_name):
        logging.info(f"Buying item {item_name}")
        if self.items[item_name].value <= self.current_cash:
            self.current_cash -= self.items[item_name].value
            self.player_inventory[item_name] += 1
            self.update_inventory_count()
            return True
        return False

    def sell(self, item_name):
        logging.info(f"Selling item {item_name}")
        if self.player_inventory.get(item_name, 0) > 0:
            if self.items[item_name].sellable:
                self.current_cash += self.items[item_name].value
                self.player_inventory[item_name] -= 1
                self.update_inventory_count()
                return True
        return False

    def generate_shop(self, items):
        for i in items:
            self.items[i.name] = i
