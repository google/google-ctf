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

import arcade.key
import engine.generics as generics
import engine.hitbox as hitbox


class Weapon(generics.GenericObject):
    def __init__(self, coords, name, weapon_type, damage_type, damage_algo,
                 tileset_path=None, collectable=True, outline=None):
        super().__init__(coords, nametype="Weapon", tileset_path=tileset_path,
                         outline=outline, can_flash=True)
        self.weapon_type = weapon_type
        self.damage_type = damage_type
        self.damage_algo = damage_algo
        self.weapon_name = name

        # Weapons start as inactive and are activated by default
        self.active = False

        # If ai_controlled, weapons behave according to algo
        self.ai_controlled = True

        # If collectable, player can pick it up
        self.collectable = collectable

        # If destroyable, the player can destroy it (assuming it's AI controlled)
        self.destroyable = True

        # The player can only use (equip) one weapon at a time
        self.equipped = False

    def draw(self):
        if not self.ai_controlled and not self.equipped:
            return
        super().draw()

    def tick(self, newly_pressed_keys, tics, player, origin="player"):
        super().tick()
        self.player = player
        if not self.active:
            return None
        if not self.ai_controlled:
            if not self.equipped:
                return None
            self.move_to_player()
            if not self.player.dead and arcade.key.SPACE in newly_pressed_keys:
                return self.fire(tics, self.player.face_towards, origin)

        # For AI controlled we pass the players to accommodate for aimbots
        else:
            return self.fire(tics, self.player, "AI")

    def move_to_player(self):
        self.place_at(self.player.x, self.player.y)
