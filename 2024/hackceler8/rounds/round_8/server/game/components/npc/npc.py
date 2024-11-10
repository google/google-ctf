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

import logging

from game.engine import generics
from game.engine import hitbox
from game.engine.keys import Keys
from game.engine.walk_data import WalkData


class Npc(generics.GenericObject):

    def __init__(self, coords, name, scale, tileset_path, walk_data='', **kwargs):
        super().__init__(
            coords,
            nametype="NPC",
            tileset_path=tileset_path,
            name=name,
            blocking=True,
        )
        # Will be overwritten
        self.game = None

        self.walk_data = WalkData(self, walk_data)
        self.should_move = True
        self.sprite.set_animation("idle-front")
        self.sprite.scale = scale
        self.freed = False
        w, h = self.sprite.get_dimensions()

        rect = hitbox.Rectangle(
            coords.x - w * scale / 2, coords.x + w * scale / 2,
            coords.y - h * scale / 2, coords.y + h * scale / 2,
        )
        self.update_hitbox(rect)

        if kwargs:
            logging.warning(f"Unused arguments provided: {kwargs} for {name}")

    def stop_moving(self):
        x = self.game.player.x
        y = self.game.player.y
        if (
                # Walking towards the player
                (self.prev_x < self.x < x)
                or (self.prev_x > self.x > x)
                or (self.prev_y < self.y < y)
                or (self.prev_y > self.y > y)
                # Already in dialogue
                or self.game.player.immobilized
        ):
            self.should_move = False

    def resume_moving(self):
        self.should_move = True

    def turn_to_player(self, x, y):
        if x >= self.x2:
            self.sprite.set_animation("idle-right")
        elif y >= self.y2:
            self.sprite.set_animation("idle-back")
        elif x <= self.x1:
            self.sprite.set_animation("idle-left")
        else:
            self.sprite.set_animation("idle-front")

    def tick(self):
        if (not self.game.player.dead and
                self.expand(20).collides(self.game.player)):
            if (Keys.E in self.game.newly_pressed_keys
                    and self.game.textbox is None):
                # Start a dialogue if we're close.
                self.turn_to_player(self.game.player.x, self.game.player.y)
                self.dialogue()
            # Don't move if the player is near.
            self.stop_moving()
        else:
            self.resume_moving()

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

    def display_textbox(self, *args, **kwargs):
        self.game.display_textbox(*args, **kwargs)

    def dialogue(self):
        raise NotImplementedError
