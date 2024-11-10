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
from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

from game import constants
from game.components.weapon.pencil import Pencil
from game.components.weapon.weapon import Weapon
from game.engine import generics
from game.engine import hitbox
from game.engine.keys import Keys
from game.engine.point import Point

if TYPE_CHECKING:
    from game.venator import Venator


class Player(generics.GenericObject):
    DIR_N = "N"
    DIR_E = "E"
    DIR_W = "W"
    DIR_S = "S"
    MAX_HEALTH = 100
    MELEE_DAMAGE = 10

    def __init__(self, coords):
        super().__init__(
            coords=coords,
            nametype="Player",
            tileset_path="resources/character/Domino.h8t",
            can_flip=True,
        )
        rect = hitbox.Rectangle(self.x - 24, self.x + 24, self.y - 26, self.y + 20)
        self.update(rect)
        self.set_health(self.MAX_HEALTH)
        self.forget_timer = 0
        self.direction = self.DIR_E
        self.face_towards = self.DIR_E
        self.prev_x = self.x
        self.prev_y = self.y
        self.last_ground_pos: Optional[Point] = None
        self.sprite.set_animation("idle-front")
        self.sprite.scale = 1
        self.last_movement: Optional[str] = None
        self.running = False
        self.can_jump = False
        self.immobilized = False
        self.jump_override = False
        self.damage_anim_counter = 0
        self.weapons: list[Weapon] = []
        self.stamina = 100
        self.is_crouching = False
        self.can_run = True
        self.melee_attack = False
        self.melee_hitbox = None
        self.melee_anim_counter = 0

        # modifiers
        self.speed_multiplier = 1.5
        self.jump_multiplier = 1
        self.damage_multiplier = 1
        self.shoot_multiplier = 1

        self.speed_bonus = False
        self.jump_bonus = False
        self.damage_bonus = False
        self.shoot_bonus = False
        self.health_bonus = False
        self.scroller_mode = False

        # Will be overwritten
        self.game: Optional[Venator] = None

    def reset_can_jump(self):
        if self.scroller_mode:
            self.can_jump = True
            return
        self.can_jump = (self.prev_y == self.y)

    def melee(self, pressed_keys, newly_pressed_keys):
        if self.dead or self.immobilized:
            return

        if self.melee_hitbox and not self.melee_attacked_this_cycle:
            for o in self.game.objects:
                if (o.nametype == "Enemy" or o.name == "fighting_boss") and not o.dead and self.melee_hitbox.collides(o):
                    o.decrease_health(self.MELEE_DAMAGE, "melee")
                    o.check_death()
                    o.sprite.set_flashing(True)
                    self.melee_attacked_this_cycle = True
        if (Keys.SPACE in newly_pressed_keys
                and not self.in_the_air
                and not (self.sprite.get_animation() == "melee" and self.melee_anim_counter > 0)):
            for weapon in self.weapons:
                if weapon.equipped:
                    self.melee_attack = False
                    return
            self.melee_attack = True
            self.melee_attacked_this_cycle = False
            self.melee_anim_counter = 50
            if self.last_movement == "right":
                self.melee_hitbox = hitbox.Rectangle(self.x + 16, self.x + 32, self.y - 28, self.y + 10)
            elif self.last_movement == "left":
                self.melee_hitbox = hitbox.Rectangle(self.x - 16, self.x - 32, self.y - 28, self.y + 10)
        elif self.sprite.get_animation() == "melee" and self.melee_anim_counter == 0:
            self.melee_attack = False
            self.melee_hitbox = None

    def tick(self, pressed_keys, newly_pressed_keys):
        self.update_movement(pressed_keys, newly_pressed_keys)
        self.melee(pressed_keys, newly_pressed_keys)
        self.update_animation()
        self.update_stamina(pressed_keys)
        super().tick()

    def update_stamina(self, pressed_keys):
        if self.running or (Keys.LSHIFT in pressed_keys):
            return
        if self.stamina < 100:
            self.stamina = min(self.stamina + 0.5, 100)

    def update_movement(self, pressed_keys, newly_pressed_keys):
        self.x_speed = 0
        if self.scroller_mode:
            self.y_speed = 0

        self.running = False
        if self.immobilized:
            return

        sprinting = (Keys.LSHIFT in pressed_keys) and self.stamina > 0

        self.is_crouching = (Keys.LCTRL in pressed_keys or Keys.S in pressed_keys)
        if self.sprite.get_animation() == "melee" or self.dead or self.damage_anim_counter > 0:  # Can't move
            return

        if self.game.has_item("forgetful"):
            if Keys.D in pressed_keys or Keys.A in pressed_keys:
                self.forget_timer += 1
            else:
                self.forget_timer = 0

            if self.forget_timer < 30:
                if Keys.D in pressed_keys and Keys.A not in pressed_keys:
                    computed_direction = self.DIR_E
                    self.change_direction(computed_direction, sprinting)
                if Keys.A in pressed_keys and Keys.D not in pressed_keys:
                    computed_direction = self.DIR_W
                    self.change_direction(computed_direction, sprinting)
        else:
            if Keys.D in pressed_keys and Keys.A not in pressed_keys:
                computed_direction = self.DIR_E
                self.change_direction(computed_direction, sprinting)
            if Keys.A in pressed_keys and Keys.D not in pressed_keys:
                computed_direction = self.DIR_W
                self.change_direction(computed_direction, sprinting)

        if Keys.W in newly_pressed_keys:
            computed_direction = self.DIR_N
            self.change_direction(computed_direction, sprinting)

        if Keys.W in pressed_keys and self.scroller_mode:
            computed_direction = self.DIR_N
            self.change_direction(computed_direction, sprinting)

        if self.scroller_mode:
            if Keys.S in pressed_keys:
                computed_direction = self.DIR_S
                self.change_direction(computed_direction, sprinting)

        if not self.scroller_mode:
            if not self.in_the_air:
                self.last_ground_pos = Point(self.x, self.y)

    def change_direction(self, direction: str, sprinting):
        self.direction = direction

        speed_multiplier = 1
        if self.direction == self.DIR_E or self.direction == self.DIR_W:
            if sprinting:
                speed_multiplier = self.speed_multiplier
                self.running = True
                self.stamina = max(0, self.stamina - 0.5)

        if self.direction == self.DIR_E or self.direction == self.DIR_W:
            self.face_towards = direction
            if direction == self.DIR_E:
                self.x_speed = self.base_x_speed * speed_multiplier
                self.sprite.set_flipped(False)
                self.last_movement = "right"
            else:
                self.last_movement = "left"
                self.x_speed = -self.base_x_speed * speed_multiplier
                self.sprite.set_flipped(True)

        if self.direction == self.DIR_N:
            logging.debug("Jumping")
            if self.scroller_mode:
                self.y_speed = self.base_x_speed * speed_multiplier
                return

            self.reset_can_jump()
            if not self.can_jump and not self.jump_override:
                logging.debug("Player in the air")
                return
                self.y_speed = self.base_y_speed * self.jump_multiplier
            else:
                self.y_speed = self.base_y_speed * speed_multiplier
            self.last_movement = "up"
            self.in_the_air = True

        if self.direction == self.DIR_S and self.scroller_mode:
            self.y_speed = -self.base_x_speed * speed_multiplier

    def update_animation(self):
        if self.dead:
            self.sprite.set_blinking(False)
            self.sprite.set_animation("die")
        else:
            if self.melee_attack:
                self.sprite.set_animation("melee")
            elif self.in_the_air:
                if self.y_speed > 0:
                    self.sprite.set_animation("jump-up")
                else:
                    self.sprite.set_animation("jump-down")
            elif self.is_crouching:
                self.sprite.set_animation("crouch")
            elif self.x_speed == 0:
                self.sprite.set_animation("idle")
            elif self.running:
                self.sprite.set_animation("run")
            else:
                self.sprite.set_animation("walk")
        if self.sprite.flashing:
            # Set damage animation for sudden damage
            if 0 < self.health < self.prev_health:
                self.damage_anim_counter = 30
        else:
            # Blink when suffering continuous damage (e.g. standing in fire).
            self.sprite.set_blinking(0 < self.health < self.prev_health)
        self.prev_health = self.health
        if self.damage_anim_counter > 0:
            self.damage_anim_counter -= 1
            if not self.melee_attack:
                self.sprite.set_animation("damage")
        if self.melee_anim_counter > 0:
            self.melee_anim_counter -= 1

    def reset(self):
        super().reset()
        self.base_x_speed = constants.PLAYER_MOVEMENT
        self.base_y_speed = constants.PLAYER_JUMP_SPEED
        self.x_speed = self.y_speed = 0
        self.set_health(self.MAX_HEALTH)
        self.stamina = 100
        self.dead = False
        self.immobilized = False

    def equip_weapon(self, weapon):
        weapon.equip(self)
        weapon.move_to_player()
        paint_mode_enabled = isinstance(weapon, Pencil)
        self.game.set_paint_mode(paint_mode_enabled)
