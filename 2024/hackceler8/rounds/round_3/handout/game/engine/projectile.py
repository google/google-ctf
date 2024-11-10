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
import itertools
import logging

from game.components.projectile import Projectile
from game.components.weapon.weapon import Weapon
from game.engine import gfx
from game.engine.generics import GenericObject
from game.components.weapon import weapon_parser
from game.engine.keys import Keys
from game.engine.point import Point


class ProjectileSystem:

    def __init__(self, game, weapon_objs: list[Weapon], targets=None):
        self.weapons = []
        for o in weapon_objs:
            w = weapon_parser.parse_weapon(o, o["coords"])
            if w is not None:
                self.weapons.append(w)
        # These are objects that can collide with projectiles, can be items or NPCs /
        # enemies
        self.targets = targets if targets is not None else []
        logging.debug(
            f"initialized projectile system with {len(self.weapons)} weapons,"
            f" {len(self.targets)} targets"
        )

        self.active_projectiles: list[Projectile] = []
        self.game = game
        if not game.is_server:
            self.sprites = gfx.CombinedLayer()

    def draw(self):
        self.sprites.clear()
        all_sprites: itertools.chain[GenericObject] = itertools.chain(self.weapons,
                                                                      (i for i in self.game.player.weapons if i.equipped),
                                                                      self.active_projectiles)
        self.sprites.add_many(i.get_draw_info() for i in all_sprites)
        self.sprites.draw()

    def tick(self, pressed_keys, newly_pressed_keys, tick):
        self._maybe_drop_weapon(newly_pressed_keys)
        # Do not tick the weapon if it's just picked.
        if not self._check_player_collisions(pressed_keys):
            if len(self.game.player.weapons) > 0:
                self._update_player_weapons(pressed_keys, newly_pressed_keys, tick)
        if len(self.active_projectiles) > 0:
            self._update_active_projectiles()

    def _check_player_collisions(self, pressed_keys):
        # Collect weapons with the space key.
        if Keys.SPACE not in pressed_keys:
            return False
        are_weapons_updated = False
        for o in self.weapons:
            if o.collides(self.game.player):
                logging.debug("Player collected with a weapon")
                self.game.player.weapons.append(o)
                self.weapons.remove(o)
                existing_equipped = any(w.equipped for w in self.game.player.weapons)
                # Not holding anything yet, so equip this.
                if not existing_equipped:
                    self.game.player.equip_weapon(o)
                are_weapons_updated = True
        return are_weapons_updated

    def _maybe_drop_weapon(self, newly_pressed_keys):
        if Keys.Q not in newly_pressed_keys:
            return
        wep = None
        weapons_size = len(self.game.player.weapons)
        for i in range(weapons_size):
            w = self.game.player.weapons[i]
            if w.equipped:
                wep = w
                if weapons_size > 1:
                    self.game.player.equip_weapon(self.game.player.weapons[(i + 1) % weapons_size])
                break
        if wep is None:
            return
        self.game.player.weapons.remove(wep)
        self.weapons.append(self._reset(wep))
        wep.equipped = False

    def _reset(self, wep):
        new_wep = weapon_parser.parse_weapon(
            {"type": wep.name}, Point(wep.x, wep.y))
        new_wep.cool_down_timer = wep.cool_down_timer
        new_wep.player = wep.player
        return new_wep

    def _update_player_weapons(self, pressed_keys, newly_pressed_keys, tics):
        for i in self.game.player.weapons:
            rval = i.tick(pressed_keys, newly_pressed_keys, tics)
            if type(rval).__name__ == "Projectile":
                logging.debug("New player-shot projectile")
                self.active_projectiles.append(rval)

    def _update_active_projectiles(self):
        for p in self.active_projectiles.copy():
            if p.check_oob(self.game.player):
                self.active_projectiles.remove(p)
                continue
            p.move(p.x_speed, p.y_speed)
            if self._check_collision(p):
                self.active_projectiles.remove(p)
                continue
            match p.origin:
                case "player":
                    self._check_player_projectile(p)
                case _:
                    self._check_enemy_projectile(p)

    def _check_player_projectile(self, p):
        for t in self.targets.copy():
            if t.dead:
                continue
            if p.collides(t):
                dmg = self._check_damage(p) * self.game.player.damage_multiplier
                if(t.decrease_health(dmg, p.weapon)):
                    t.sprite.set_flashing(True)
                    t.check_death()
                    logging.info(f"New target health: {t.health}")
                    logging.info(f"New target health: {t.dead}")
                if (t.dead and not t.does_respawn) or t.destructing:
                    logging.debug("Target destroyed sir")
                    self.targets.remove(t)

    def _check_enemy_projectile(self, p):
        if self.game.player.collides(p):
            dmg = self._check_damage(p)
            self.game.player.decrease_health(dmg, "enemy")
            if not self.game.player.dead:
                self.game.player.sprite.set_flashing(True)

    def _check_damage(self, p):
        logging.debug("removing projectile")
        if p in self.active_projectiles:
            self.active_projectiles.remove(p)
        return p.base_damage

    def _check_collision(self, p):
        return self.game.physics_engine.check_collision_by_type(p, ['Wall'])
