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

from game.components.player import Player
from game.components.env_element import EnvModifier
from game.constants import GRAVITY_CONSTANT
from game.constants import PLAYER_JUMP_SPEED
from game.constants import PLAYER_MOVEMENT_SPEED
from game.engine import generics


class PhysicsEngine:
    generic_mod = EnvModifier("generic", 1, 1, 1, False)
    current_mod = generic_mod

    def __init__(
            self,
            game,
            gravity: int = GRAVITY_CONSTANT,
            objects: list[generics.GenericObject] = None,
    ):

        self.game = game
        self.og_gravity = gravity
        self.og_jump_speed = PLAYER_JUMP_SPEED
        self.og_movement_speed = PLAYER_MOVEMENT_SPEED

        self.gravity = self.og_gravity
        self.jump_speed = self.og_jump_speed
        self.movement_speed = self.og_movement_speed

        self.jump_override = False

        # need to be a series of objects that are subject to gravity with coords
        self.objects = objects
        self.player = self._get_player()
        self.moving_objects = [o for o in self.objects if o.enable_moving_physics]
        self.moving_objects += [self.player]

        self.debug_objs = []
        self.env_tiles = []
        self._apply_modifier()

    def _get_player(self):
        tmp = [o for o in self.objects if o.nametype == "Player"]
        if len(tmp) != 1:
            logging.critical(
                "Cannot have more than one player, this smells like cheat"
            )
            self.game.cheating_detected = True
        logging.debug("Player initialized")
        self.objects.remove(tmp[0])
        return tmp[0]

    def tick(self):
        if self.gravity == 0:
            self.player.scroller_mode = True
        else:
            self.player.scroller_mode = False
        for o in self.moving_objects:
            o.update_position()
        self._detect_collision()
        self._detect_env_mod()
        for o in self.objects:
            if o.in_the_air:
                if o.y_speed != 0:
                    o.y_speed -= self.gravity

        for o in self.moving_objects:
            if o.in_the_air:
                o.y_speed -= self.gravity

    def add_moving_object(self, o):
        self.moving_objects.append(o)

    def add_generic_object(self, o):
        self.objects.append(o)

    def remove_generic_object(self, o):
        if o in self.objects:
            self.objects.remove(o)
        if o in self.moving_objects:
            self.moving_objects.remove(o)

    def _get_collisions_list(self, player):
        collisions_x, collisions_y, non_blocking = [], [], []
        for o1 in self.objects:
            if o1 is player:
                continue
            if o1.collides(player):
                mpv = o1.get_mpv(player)
                if not o1.blocking:
                    logging.debug(f"Collision with non blocking item ({o1.nametype})")
                    non_blocking.append(o1)
                    continue
                logging.debug(f"Collision with {o1}")
                if int(round(mpv.x, 2)) == 0:
                    collisions_y.append((o1, mpv))
                elif int(round(mpv.y, 2)) == 0:
                    collisions_x.append((o1, mpv))
        return collisions_x, collisions_y, non_blocking

    def check_collision_by_type(self, obj, types):
        for o1 in self.objects:
            if o1 is obj:
                continue
            if o1.nametype not in types:
                continue
            if o1.collides(obj):
                return True
        return False

    def _align_edges(self, obj):
        collisions_x, collisions_y, _ = self._get_collisions_list(obj)
        if len(collisions_x) + len(collisions_y) == 0:
            obj.in_the_air = True
            return
        for o, mpv in collisions_x:
            self._align_x_edge(obj, o, mpv.x)

        _, collisions_y, _ = self._get_collisions_list(obj)
        logging.debug(f"There are {len(collisions_y)} collisions on the y axis")
        for o, mpv in collisions_y:
            self._align_y_edge(obj, o, mpv.y)

    def _detect_collision(self):
        for o in self.moving_objects:
            self._align_edges(o)

        _, _, non_blocking = self._get_collisions_list(self.player)

        for n in non_blocking:
            logging.debug(f"Collision with {n.nametype}")
            n.on_player_collision(self.player)

    def _detect_env_mod(self):
        for t in self.env_tiles:
            if t.collides(self.player):
                PhysicsEngine.current_mod = t.modifier
                self._apply_modifier()
                return
        PhysicsEngine.current_mod = PhysicsEngine.generic_mod
        self._apply_modifier()

    def _apply_modifier(self):
        self.jump_speed = self.og_jump_speed * PhysicsEngine.current_mod.jump_speed
        self.movement_speed = self.og_movement_speed * PhysicsEngine.current_mod.walk_speed
        self.gravity = self.og_gravity * PhysicsEngine.current_mod.gravity
        self.player.base_x_speed = self.movement_speed
        self.player.base_y_speed = self.jump_speed
        self.jump_override = PhysicsEngine.current_mod.jump_override
        self.player.jump_override = self.jump_override

    @staticmethod
    def _align_y_edge(player, o1, mpv):
        if int(round(mpv, 2)) == 0:
            return
        fall_damage = max(abs(player.y_speed) - 6 , 0) * 10
        if PhysicsEngine.current_mod.name == "generic" and fall_damage > 0:
            player.decrease_health(points=fall_damage)
            player.sprite.set_flashing(True)
        player.y_speed = 0
        logging.debug(mpv)
        if mpv > 0:
            logging.debug(
                "Positive MPV, collision was downwards (player on the ground)"
            )
            player.move(0, o1.get_highest_point() - player.get_lowest_point())
            player.in_the_air = False

        else:
            logging.debug(
                "Negative MPV, collision was upward"
            )
            delta_e = 0
            player.move(0, o1.get_lowest_point() - delta_e - player.get_highest_point())

    @staticmethod
    def _align_x_edge(player, o1, mpv):
        if int(round(mpv, 2)) == 0:
            return
        player.x_speed = 0

        logging.debug(mpv)
        if mpv < 0:
            logging.debug("Negative MPV, collision was right")
            player.move(o1.get_leftmost_point() - player.get_rightmost_point(), 0)
            player.x_speed = 0
        else:
            logging.debug("Positive MPV, collision was left")
            player.move(o1.get_rightmost_point() - player.get_leftmost_point(), 0)
            player.x_speed = 0
