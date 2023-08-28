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


class CombatSystem:
    def __init__(self, weapons, targets=None):
        if targets is None:
            targets = []

        self.weapons = weapons
        # These are objects that can collide with projectiles, can be items or NPCs /
        # enemies
        self.targets = [w for w in self.weapons if w.destroyable] + targets
        self.active_weapons = [w for w in self.weapons if w.active]
        logging.debug(
            f"initialized combat system with {len(self.weapons)} weapons,"
            f" {len(self.targets)} targets and {len(self.active_weapons)} weapons")

        # Variable stuff
        self.player_weapons = []
        self.active_projectiles = []

        # Technically this shouldn't happen
        self.player = None

    def spawn_weapon(self, w):
        self.active_weapons.append(w)

    def draw(self):
        for i in self.weapons:
            i.draw()
        for i in self.player_weapons:
            i.draw()
        for i in self.active_projectiles:
            i.draw()

    def tick(self, newly_pressed_keys, tick):
        if self.player is not None:
            self._check_player_collisions()
        if len(self.active_weapons + self.player_weapons) > 0:
            self._update_active_weapons(newly_pressed_keys, tick)
        if len(self.active_projectiles) > 0:
            self._update_active_projectiles()

    def _check_player_collisions(self):
        for o in self.weapons:
            c, _ = o.collides(self.player)
            if c:
                if o.collectable:
                    logging.debug("Player collected with a weapon")
                    logging.debug("Weapon is collectable!")
                    o.active = True
                    o.ai_controlled = False
                    self.player_weapons.append(o)
                    self.weapons.remove(o)
                    if not any(w.equipped for w in self.player_weapons):
                        # Not holding anything yet, so equip this.
                        o.equipped = True

    def _update_active_weapons(self, newly_pressed_keys, tics):
        for i in self.player_weapons:
            rval = i.tick(newly_pressed_keys, tics, self.player)
            if type(rval).__name__ == "Projectile":
                logging.debug("New player-shot projectile")
                self.active_projectiles.append(rval)

        for i in self.active_weapons:
            rval = i.tick(None, tics, self.player, "ai")
            if type(rval).__name__ == "Projectile":
                logging.debug("New AI-shot projectile")
                self.active_projectiles.append(rval)

    def _update_active_projectiles(self):
        for p in self.active_projectiles.copy():
            if p.check_oob():
                self.active_projectiles.remove(p)
                continue
            p.move(p.x_speed, p.y_speed)
            match p.origin:
                case "player":
                    self._check_player_projectile(p)
                case _:
                    self._check_enemy_projectile(p)

    def _check_player_projectile(self, p):
        for t in self.targets.copy():
            c, _ = p.collides(t)
            if c:
                dmg = self._check_damage(p)
                t.decrease_health(dmg)
                t.sprite.set_flashing(True)
                t.check_death()
                logging.info(f"New target health: {t.health}")
                logging.info(f"New target health: {t.dead}")
                if t.dead:
                    logging.debug("Target destroyed sir")
                    if t in self.active_weapons:
                        self.active_weapons.remove(t)
                        self.weapons.remove(t)
                        self.targets.remove(t)

    def _check_enemy_projectile(self, p):
        c, _ = self.player.collides(p)
        if c:
            dmg = self._check_damage(p)
            self.player.decrease_health(dmg)
            if not self.player.dead:
                self.player.sprite.set_flashing(True)

    def _check_damage(self, p):
        logging.debug(
            f"checking damage with damage algo {p.damage_algo, p.damage_type}")
        match p.damage_type:
            case "single":
                return self._deal_single_damage(p)

    def _deal_single_damage(self, p):
        logging.debug("removing projectile")
        self.active_projectiles.remove(p)
        return p.base_damage
