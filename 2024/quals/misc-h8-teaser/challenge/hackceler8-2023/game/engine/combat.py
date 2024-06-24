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

import arcade
import logging
import pytiled_parser
from copy import deepcopy
from components.weapon import weapon_types


class CombatSystem:
    def __init__(self, game, weapons, targets=None):
        if targets is None:
            targets = []

        self.weapons = deepcopy(weapons)
        self.original_weapons = weapons
        # These are objects that can collide with projectiles, can be items or NPCs /
        # enemies
        self.targets = [w for w in self.weapons if w.destroyable] + targets
        self.active_weapons = [w for w in self.weapons if w.active]
        logging.debug(
            f"initialized combat system with {len(self.weapons)} weapons,"
            f" {len(self.targets)} targets and {len(self.active_weapons)} weapons")

        # Variable stuff
        self.active_projectiles = []

        self.game = game

    def draw(self):
        for i in self.weapons:
            i.draw()
        for i in self.game.player.weapons:
            i.draw()
        for i in self.active_projectiles:
            i.draw()

    def tick(self, pressed_keys, newly_pressed_keys, tick):
        self._maybe_drop_weapon(newly_pressed_keys)
        if len(self.active_projectiles) > 0:
            self._update_active_projectiles()
        if len(self.active_weapons + self.game.player.weapons) > 0:
            self._update_active_weapons(pressed_keys, newly_pressed_keys, tick)
        self._check_player_collisions(newly_pressed_keys)

    def _check_player_collisions(self, newly_pressed_keys):
        # Collect weapons with the space key.
        if arcade.key.SPACE not in newly_pressed_keys:
            return
        for o in self.weapons:
            c, _ = o.collides(self.game.player)
            if c:
                if o.collectable:
                    logging.debug("Player collected with a weapon")
                    logging.debug("Weapon is collectable!")
                    o.active = True
                    o.ai_controlled = False
                    self.game.player.weapons.append(o)
                    self.weapons.remove(o)
                    if not any(w.equipped for w in self.game.player.weapons):
                        # Not holding anything yet, so equip this.
                        o.equipped = True

    def _maybe_drop_weapon(self, newly_pressed_keys):
        if arcade.key.Q not in newly_pressed_keys:
            return
        wep = None
        weapons_size = len(self.game.player.weapons)
        for i in range(weapons_size):
            w = self.game.player.weapons[i]
            if w.equipped:
                wep = w
                if weapons_size > 1:
                    self.game.player.weapons[(i+1) % weapons_size].equipped = True
                break
        if wep is None:
            return
        self.game.player.weapons.remove(wep)
        self.weapons.append(wep)
        wep.active = False
        wep.ai_controlled = True
        wep.equipped = False

    def _update_active_weapons(self, pressed_keys, newly_pressed_keys, tics):
        for i in self.game.player.weapons:
            i.game = self.game
            rval = i.tick(pressed_keys, newly_pressed_keys, tics, self.game.player)
            if type(rval).__name__ == "Projectile":
                logging.debug("New player-shot projectile")
                self.active_projectiles.append(rval)
                self.game.physics_engine.moving_objects.append(rval)

        for i in self.active_weapons:
            rval = i.tick(None, None, tics, self.game.player, "ai")
            if type(rval).__name__ == "Projectile":
                logging.debug("New AI-shot projectile")
                self.active_projectiles.append(rval)
                self.game.physics_engine.moving_objects.append(rval)

    def _update_active_projectiles(self):
        for p in self.active_projectiles.copy():
            if p.collided or p.check_oob(self.game.player):
                self.active_projectiles.remove(p)
                self.game.physics_engine.remove_generic_object(p)
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
            c, _ = p.collides(t)
            if c:
                dmg = self._check_damage(p)
                t.decrease_health(dmg)
                t.sprite.set_flashing(True)
                t.check_death()
                logging.info(f"New target health: {t.health}")
                logging.info(f"New target health: {t.dead}")
                if t.dead and not t.respawn:
                    logging.debug("Target destroyed sir")
                    self.targets.remove(t)
                    if t in self.active_weapons:
                        self.active_weapons.remove(t)
                        self.weapons.remove(t)
                        self._remove_original_weapon(t)

    def _check_enemy_projectile(self, p):
        c, _ = self.game.player.collides(p)
        if c:
            dmg = self._check_damage(p)
            self.game.player.decrease_health(dmg)
            if not self.game.player.dead:
                self.game.player.sprite.set_flashing(True)

    def _check_damage(self, p):
        logging.debug(
            f"checking damage with damage algo {p.damage_algo, p.damage_type}")
        match p.damage_type:
            case "single":
                return self._deal_single_damage(p)

    def _deal_single_damage(self, p):
        logging.debug("removing projectile")
        self.active_projectiles.remove(p)
        self.game.physics_engine.remove_generic_object(p)
        return p.base_damage

    def _remove_original_weapon(self, t):
        for w in self.original_weapons:
            if not w.destroyable:
                continue
            if (w.x, w.y) == (t.x, t.y):
                self.original_weapons.remove(w)
