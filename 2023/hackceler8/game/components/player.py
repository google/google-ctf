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
    MAX_HEALTH = 100

    def __init__(self, coords, outline):
        super().__init__(coords=coords, nametype="Player",
                         tileset_path=self.SCROLLER_TILESET,
                         outline=outline,
                         can_flip=True, can_flash=True)

        self.set_health(self.MAX_HEALTH)
        self.direction = self.DIR_S
        self.face_towards = self.DIR_E
        self.prev_x = self.x
        self.prev_y = self.y
        self.push_speed = 0
        self.can_control_movement = True
        self.sprite.set_animation("idle-front")
        self.sprite.scale = 1
        self.last_movement = None
        self.running = False
        self.platformer_rules = False
        self.allowed_directions = set()
        self.reset_movements()
        self.jump_override = False
        self.inverted_controls = False
        self.weapons = []

        # modifiers
        self.speed_multiplier = 1.5
        self.jump_multiplier = 1

        self.speed_bonus = False
        self.jump_bonus = False
        self.health_bonus = False

        # Will be overwritten
        self.game = None

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
        if self.immobilized():
            self.x_speed = self.y_speed = 0
        self.update_animation()
        super().tick()

    def update_movement(self, pressed_keys, reset_speed=True):
        self.x_speed = 0
        if reset_speed:
            self.reset_speed()

        if self.dead:  # Can't move
            return

        self.running = False
        if self.can_control_movement:
            sprinting = arcade.key.LSHIFT in pressed_keys
            if (arcade.key.D in pressed_keys) and (arcade.key.A not in pressed_keys):
                computed_direction = self.DIR_E if not self.inverted_controls else self.DIR_W
                self.change_direction(computed_direction, sprinting)

            if (arcade.key.A in pressed_keys) and (arcade.key.D not in pressed_keys):
                computed_direction = self.DIR_W if not self.inverted_controls else self.DIR_E
                self.change_direction(computed_direction, sprinting)

            if (arcade.key.W in pressed_keys) and (arcade.key.S not in pressed_keys):
                computed_direction = self.DIR_N if not self.inverted_controls else self.DIR_S
                self.change_direction(computed_direction, sprinting)

            if (arcade.key.S in pressed_keys) and (arcade.key.W not in pressed_keys):
                computed_direction = self.DIR_S if not self.inverted_controls else self.DIR_N
                self.change_direction(computed_direction, sprinting)

        if self.can_control_movement:
            self.push_speed = max(0, self.push_speed - 125)
        if self.push_speed > 0:
            match self.direction:
                case self.DIR_N:
                    self.y_speed += self.push_speed
                case self.DIR_S:
                    self.y_speed -= self.push_speed
                case self.DIR_E:
                    self.x_speed += self.push_speed
                case self.DIR_W:
                    self.x_speed -= self.push_speed

    def change_direction(self, direction, sprinting):
        self.direction = direction

        speed_multplier = 1
        if not self.platformer_rules or (
                self.direction == self.DIR_E or self.direction == self.DIR_W):
            if sprinting:
                speed_multplier = self.speed_multiplier
                self.running = True

        if self.direction == self.DIR_E or self.direction == self.DIR_W:
            self.face_towards = direction
            if direction == self.DIR_E:
                if "L" in self.allowed_directions:
                    self.x_speed = self.base_x_speed * speed_multplier
                    self.sprite.set_flipped(False)
                    self.last_movement = "right"
            else:
                if "R" in self.allowed_directions:
                    self.last_movement = "left"
                    self.x_speed = -self.base_x_speed * speed_multplier
                    if "R" in self.allowed_directions:
                        if self.platformer_rules:
                            self.sprite.set_flipped(True)

        if self.direction == self.DIR_N:
            logging.debug("Jumping")
            if self.platformer_rules and self.in_the_air and not self.jump_override:
                logging.debug("Player in the air")
                return
            if "U" in self.allowed_directions:
                if self.platformer_rules:
                    self.y_speed = self.base_y_speed * self.jump_multiplier
                else:
                    self.y_speed = self.base_y_speed * speed_multplier
                self.last_movement = "up"
                self.in_the_air = True
            else:
                logging.error("not allowed")

        if self.direction == self.DIR_S:
            if "D" in self.allowed_directions:
                if self.in_the_air:
                    if not self.platformer_rules:
                        # This is a hack because we're still clipping through
                        self.y_speed = -self.base_y_speed * speed_multplier
                        self.last_movement = "down"

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

    def regen(self):
        self.set_health(self.MAX_HEALTH)
        self.dead = False
        self.x_speed = self.y_speed = self.push_speed = 0

    def wear_item(self, i=None):
        if not self.platformer_rules:
            return
        if i is None:
            w = [i for i in self.game.items[::-1] if i.wearable]
            if len(w) == 0:
                return
            i = w[0]
        for item in self.game.items:
            if item.wearable and item != i:
                item.worn = False
        i.worn = True
        self.sprite.set_texture(
            "resources/character/AnimationSheet_%s.png" % i.name.capitalize())

    def immobilized(self):
        # Don't move while charging a weapon.
        for w in self.weapons:
            if w.equipped and w.charging:
                return True
        return False

    def modify(self, items):
        for item in items:
            self._modify(item.name)

    def _modify(self, item):
        match item:
            case 'goggles':
                if not self.health_bonus:
                    self.MAX_HEALTH = 200
                    self.health_bonus = True
                    self.set_health(self.MAX_HEALTH)
                    logging.info("Max health permanently set to 200")
            case 'magnet':
                pass
            case 'boots':
                if not self.speed_bonus:
                    self.speed_multiplier = 2
                    self.speed_bonus = True
                    logging.info("Speed multiplier permanently increased")
            case 'noogler':
                if not self.jump_bonus:
                    self.jump_multiplier = 2
                    self.jump_bonus = True
                    logging.info("Jump multiplier permanently increased")
