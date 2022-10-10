# Copyright 2022 Google LLC
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

from arcade import gui

from components import player, collectable
from . import menu
import environ


class InventoryMenu:
    def __init__(self, game):
        self.v_box = gui.UIBoxLayout()
        label = gui.UILabel(text="Bag", font_size=15)
        self.v_box.add(gui.UIBoxLayout(vertical=False, children=[label]))
        self.v_box.add(gui.UIWidget(width=1, height=20))

        self.v_box.add(gui.UIWidget(width=1, height=20))
        self.window = menu.BorderedMenu(game, child=self.v_box)

        self.widget = gui.UIAnchorWidget(
            anchor_x="left",
            anchor_y="center",
            child=self.window)

        for i in range(len(game.player.inventory)):
            item: collectable.Collectable = game.player.inventory[i]
            text = item.inventory_text or item.entity.name
            use_button = gui.UIFlatButton(
                text=text, width=200, height=25, style={"bg_color": (64, 64, 64)})
            button_wrapper = use_button.with_border(
                width=2, color=(0, 127, 0)).with_space_around(
                top=0, right=20, bottom=0, left=20)
            self.v_box.add(button_wrapper)
            use_button.on_click = self.use_item
            use_button.item_idx = i

    def use_item(self, event):
        item_idx = event.source.item_idx
        environ.game.player.use_item(item_idx)
        environ.client.close_inventory()