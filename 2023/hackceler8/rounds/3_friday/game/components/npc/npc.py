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

from engine import generics
from engine import hitbox
from engine.walk_data import WalkData
import constants


class Npc(generics.GenericObject):
    def __init__(self, coords, name, walk_data, scale, tileset_path):
        super().__init__(coords, nametype="NPC", tileset_path=tileset_path,
                         name=name, can_flash=True)
        # Will be overwritten
        self.game = None
        self.display_textbox = lambda _x: logging.fatal("Npc.display_textbox not set")

        self.walk_data = WalkData(self, walk_data)
        self.blocking = True
        self.should_move = True
        self.sprite.set_animation("idle-front")
        self.sprite.scale = scale
        w, h = self.sprite.get_dimensions()
        outline = [
            hitbox.Point(coords.x - w * scale / 2, coords.y - h * scale / 2),
            hitbox.Point(coords.x + w * scale / 2, coords.y - h * scale / 2),
            hitbox.Point(coords.x + w * scale / 2, coords.y + h * scale / 2),
            hitbox.Point(coords.x - w * scale / 2, coords.y + h * scale / 2),
        ]
        self._update(outline)

    def stop_moving(self, x, y):
        # Only stop moving if walking towards the player
        if ((self.prev_x < self.x < x) or
                (self.prev_x > self.x > x) or
                (self.prev_y < self.y < y) or
                (self.prev_y > self.y > y)):
            self.should_move = False

    def resume_moving(self):
        self.should_move = True

    def turn_to_player(self, x, y):
        rect = self.get_rect()
        if x >= rect.x2():
            self.sprite.set_animation("idle-right")
        elif y >= rect.y2():
            self.sprite.set_animation("idle-back")
        elif x <= rect.x1():
            self.sprite.set_animation("idle-left")
        else:
            self.sprite.set_animation("idle-front")

    def tick(self):
        super().tick()
        direction = self.sprite.animation.name.split("-")[1]
        if len(self.walk_data.data) == 0 or not self.should_move:
            self.sprite.set_animation(f"idle-{direction}")
            return

        walk_dir = self.walk_data.walk(self.game)
        match walk_dir:
            case "I":
                self.sprite.set_animation(f"idle-{direction}")
            case "N":
                self.sprite.set_animation("walk-back")
            case "E":
                self.sprite.set_animation("walk-right")
            case "S":
                self.sprite.set_animation("walk-front")
            case "W":
                self.sprite.set_animation("walk-left")


class BarkNpc(Npc):
    def __init__(self, coords, name, walk_data):
        super().__init__(coords, name, walk_data, scale=1,
                         tileset_path="resources/NPCs/Dog_NPC.tmx")

    def dialogue(self):
        self.display_textbox("BARK BARK!")
