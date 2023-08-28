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

import arcade

import constants
from engine import generics
from engine import hitbox


class Player(generics.GenericObject):
    DIR_N = "N"
    DIR_E = "E"
    DIR_S = "S"
    DIR_W = "W"
    PLATFORMER_TILESET = "resources/character/AnimationSheet_Mew.tmx"
    SCROLLER_TILESET = "resources/character/AnimationSheet_OverheadMew.tmx"

    def __init__(self, coords, outline):
        super().__init__(coords=coords, nametype="Player",
                         tileset_path=self.SCROLLER_TILESET,
                         outline=outline,
                         can_flip=True, can_flash=True)

        self.direction = self.DIR_S
        self.face_towards = self.DIR_E
        self.prev_x = self.x
        self.prev_y = self.y
        self.sprite.set_animation("idle-front")
        self.sprite.scale = 1
        self.last_movement = None
        self.running = False
        self.platformer_rules = False
        self.allowed_directions = set()
        self.reset_movements()
        self.jump_override = False

    def safe_remove_direction(self, direction):
        if direction in self.allowed_directions:
            self.allowed_directions.remove(direction)

    def reset_movements(self):
        self.allowed_directions = set(["U", "D", "L", "R"])

    def is_falling(self, bound):
        if self.y_speed < 0:
            return "down"
        return bound

    def tick(self, pressed_keys, _newly_pressed_keys, reset_speed=True):
        self.update_movement(pressed_keys, reset_speed)
        self.update_animation()
        super().tick()

    def update_movement(self, pressed_keys, reset_speed=True):
        self.x_speed = 0
        if reset_speed:
            self.reset_speed()

        if self.dead:  # Can't move
            return

        running_mod = 1
        self.running = False
        if (arcade.key.D in pressed_keys) and (arcade.key.A not in pressed_keys):
            self.direction = self.DIR_E
            self.face_towards = self.DIR_E
            if arcade.key.LSHIFT in pressed_keys:
                running_mod = 1.5
                self.running = True
            if "L" in self.allowed_directions:
                self.x_speed = self.base_x_speed * running_mod
                self.sprite.set_flipped(False)
                self.last_movement = "right"

        if (arcade.key.A in pressed_keys) and (arcade.key.D not in pressed_keys):
            self.direction = self.DIR_W
            self.face_towards = self.DIR_W
            if arcade.key.LSHIFT in pressed_keys:
                running_mod = 1.5
                self.running = True
            if "R" in self.allowed_directions:
                self.x_speed = -self.base_x_speed * running_mod
                if self.platformer_rules:
                    self.sprite.set_flipped(True)
                self.last_movement = "left"

        if (arcade.key.W in pressed_keys) and (arcade.key.S not in pressed_keys):
            logging.debug("Jumping")
            self.direction = self.DIR_N
            if self.platformer_rules and self.in_the_air and not self.jump_override:
                logging.debug("Player in the air")
                return
            if "U" in self.allowed_directions:
                self.y_speed = self.base_y_speed
                self.last_movement = "up"
                self.in_the_air = True
            else:
                logging.error("not allowed")

        if (arcade.key.S in pressed_keys) and (arcade.key.W not in pressed_keys):
            self.direction = self.DIR_S
            if "D" in self.allowed_directions:
                if self.in_the_air:
                    if not self.platformer_rules:
                        # This is a hack because we're still clipping through
                        self.y_speed = -self.base_y_speed
                        self.last_movement = "down"

    def place_at(self, x, y):
        self.move(x - self.x, y - self.y)

    def update_position(self):
        self.prev_x = self.x
        self.prev_y = self.y
        self.move(constants.TICK_S * self.x_speed, constants.TICK_S * self.y_speed)
        self.update_hitbox([
            hitbox.Point(self.x - 16, self.y - 16),
            hitbox.Point(self.x + 16, self.y - 16),
            hitbox.Point(self.x + 16, self.y + 16),
            hitbox.Point(self.x - 16, self.y + 16),
        ])
        logging.debug(f"New position is {self.x, self.y}")

    def update_animation(self):
        if self.dead:
            self.sprite.set_blinking(False)
            self.sprite.set_animation("die")
        else:
            if not self.platformer_rules:  # Overhead animations
                suffix = ""
                match self.direction:
                    case self.DIR_N:
                        suffix = "back"
                    case self.DIR_E:
                        suffix = "right"
                    case self.DIR_S:
                        suffix = "front"
                    case self.DIR_W:
                        suffix = "left"

                prefix = (
                    "idle" if (self.x_speed == 0 and self.y_speed == 0) else "walk")
                self.sprite.set_animation(prefix + "-" + suffix)
            else:
                if self.in_the_air:
                    if self.y_speed > 0:
                        self.sprite.set_animation("jump-up")
                    else:
                        self.sprite.set_animation("jump-down")
                elif self.x_speed == 0:
                    self.sprite.set_animation("idle")
                elif self.running:
                    self.sprite.set_animation("run")
                else:
                    self.sprite.set_animation("walk")

        # Blink when suffering continuous damage (e.g. standing in fire).
        if not self.sprite.flashing:
            self.sprite.set_blinking(0 < self.health < self.prev_health)
        self.prev_health = self.health
