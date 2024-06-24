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

from components.player import Player
from engine import generics
from engine import quadtree
from collections import deque

from constants import GRAVITY_CONSTANT
from constants import PLAYER_JUMP_SPEED
from constants import PLAYER_MOVEMENT_SPEED
from constants import PLAYER_RUN_SPEED


class PhysicsEngine:
    def __init__(self,
                 gravity: int = GRAVITY_CONSTANT,
                 platformer_rules: bool = True,
                 objects: list[
                     generics.GenericObject] = None, qt=None, obj_map=None,
                 static_objects: list[
                     generics.GenericObject] = None):

        self.og_gravity = gravity
        self.og_jump_speed = PLAYER_JUMP_SPEED
        self.og_movement_speed = PLAYER_MOVEMENT_SPEED
        self.og_run_speed = PLAYER_RUN_SPEED

        self.gravity = None
        self.jump_speed = None
        self.movement_speed = None
        self.run_speed = None

        self.current_env = "generic"
        self.jump_override = False

        self.original_params = [
            self.og_gravity,
            self.og_jump_speed,
            self.og_movement_speed,
            self.og_run_speed
        ]

        # need to be a series of objects that are subject to gravity with coords
        self.objects = objects
        self.static_objects = static_objects
        self.obj_map = obj_map
        self.player = self._get_player()
        self.moving_platforms = []
        self.moving_objects = deque(maxlen=9)
        self.moving_objects += [o for o in self.objects if o.enable_moving_physics]
        self.moving_objects += [self.player]

        self.qt = qt
        self.platformer_rules = self.player.platformer_rules = platformer_rules
        if self.platformer_rules:
            self.player.load_sprite(Player.PLATFORMER_TILESET)
            self.player.wear_item()
        self.debug_objs = []
        self.env_tiles = []
        self.tmp_loot = []
        self.exit_on_next = False
        self._reset_parameters()

    def _reset_parameters(self):
        self.gravity, self.jump_speed, self.movement_speed, self.run_speed = self.original_params
        self.jump_override = False
        self.player.jump_override = self.jump_override
        self.player.base_x_speed = self.movement_speed
        self.player.base_y_speed = self.jump_speed if self.platformer_rules else self.movement_speed
        self.current_env = "generic"

    def _get_player(self):
        tmp = [o for o in self.objects if o.nametype == "Player"]
        if len(tmp) != 1:
            logging.critical("Cannot have more than one player, this smells like cheat")
            self.exit_on_next = True
        logging.debug("Player initialized")
        self.objects.remove(tmp[0])
        return tmp[0]

    def tick(self):
        for o in self.moving_objects:
            o.update_position()
        logging.debug(self.player.bounds.x)
        self.player.reset_movements()
        self._detect_collision()

        if self.platformer_rules:
            self._tick_platformer()

        logging.debug(self.player.in_the_air)
        logging.debug(self.player.y_speed)

    def _tick_platformer(self):
        self._detect_env_mod()
        for o in self.objects:
            if o.in_the_air:
                if o.y_speed != 0:
                    o.y_speed -= self.gravity

        for o in self.moving_objects:
            if o.in_the_air and o.affected_by_gravity:
                o.y_speed -= self.gravity

        for i in self.moving_platforms:
            i.game = self.game
            i.move_around()

    def _get_collisions_qt(self):
        region_of_interest = quadtree.Bounds(
            self.player.bounds.x - 32,
            self.player.bounds.y + 32,
            80,
            80,
            "current_search_area"
        )

        pots = self.qt.query(region_of_interest)
        objs = [self.obj_map[i.idi] for i in pots]

        return objs

    def add_moving_object(self, o):
        self.moving_objects.append(o)

    def add_generic_object(self, o):
        self.objects.append(o)

    def remove_generic_object(self, o):
        if o in self.objects:
            self.objects.remove(o)
        if o in self.static_objects:
            self.static_objects.remove(o)
        if o in self.moving_platforms:
            self.moving_platforms.remove(o)
        if o in self.moving_objects:
            self.moving_objects.remove(o)

    def _get_collisions_list(self, o):
        collisions_x, collisions_y, non_blocking = [], [], []
        for o1 in self.objects + self.static_objects + self.moving_platforms:
            if o1 is o:
                continue
            if o1.nametype in {"Toggle"}:
                continue
            c, mpv = o1.collides(o)
            if c:
                if (o1.nametype in {"Item", "ExitArea", "Ouch", "Fire", "Arena",
                                    "Portal", "Spike", "Switch", "Soul", "SpeedTile",
                                    "Flag"}
                        or o1.nametype == "LogicDoor" and not o1.blocking
                        or o1.nametype == "Enemy" and (o1.dead or not o1.blocking or o.nametype == "Projectile")):
                    logging.debug(f"Collision with non blocking item ({o1.nametype})")
                    non_blocking.append(o1)
                    continue
                logging.debug(f"Collision with {o1.unique_id}")
                if mpv[0] == 0.0:
                    logging.debug("This is a Y collision")
                    collisions_y.append((o1, mpv))
                elif mpv[1] == 0.0:
                    logging.debug("This is a X collision")
                    collisions_x.append((o1, mpv))
        return collisions_x, collisions_y, non_blocking

    def _align_edges(self, o):
        collisions_x, collisions_y, non_blocking = self._get_collisions_list(o)
        o.collided = len(collisions_x) + len(collisions_y) > 0

        if len(collisions_x) + len(collisions_y) + len(non_blocking) == 0:
            o.in_the_air = True
            return

        for o2, mpv in collisions_x:
            self._align_x_edge(o, o2, mpv[0])

        _, collisions_y, non_blocking = self._get_collisions_list(o)
        logging.debug(f"There are {len(collisions_y)} collisions on the y axis")
        for o2, mpv in collisions_y:
            self._align_y_edge(o, o2, mpv[1])

    def _detect_collision(self):
        for o in self.moving_objects:
            self._align_edges(o)

        _, _, non_blocking = self._get_collisions_list(self.player)

        for n in non_blocking:
            logging.debug(f"Collision with {n.nametype}")
            match n.nametype:
                case "Item":
                    if n.collectable:
                        logging.info(f"Player collected new item {n.name}")
                        self.tmp_loot.append(n)
                        self.objects.remove(n)
                case "ExitArea":
                    self.exit_on_next = True
                    logging.debug("Player reached exit")

    def _detect_env_mod(self):
        for t in self.env_tiles:
            c, _ = t.collides(self.player)
            if c:
                self._apply_modifier(t.modifier)
                return
        if self.current_env != "generic":
            logging.debug("Resetting parameters")
            self._reset_parameters()

    def _apply_modifier(self, modifier):
        if self.current_env == modifier.name:
            return
        logging.debug(f"Current player speed: {self.player.base_x_speed}")
        logging.debug(f"Current player jump: {self.player.base_y_speed}")
        logging.debug(f"Applying modifier {modifier.name}")
        self.jump_speed = self.og_jump_speed * modifier.jump_speed
        self.movement_speed = self.og_movement_speed * modifier.walk_speed
        self.gravity = self.og_gravity * modifier.gravity
        logging.debug(self.movement_speed)
        logging.debug(self.jump_speed)
        self.player.base_x_speed = self.movement_speed
        self.player.base_y_speed = self.jump_speed
        self.current_env = modifier.name
        self.jump_override = modifier.jump_override
        self.player.jump_override = self.jump_override
        logging.debug(f"Current player speed: {self.player.base_x_speed}")
        logging.debug(f"Current player jump: {self.player.base_y_speed}")

    @staticmethod
    def _align_y_edge(player, o1, mpv):
        player.y_speed = 0
        if player.x_sticky:
            player.x_speed = 0
        logging.debug(mpv)
        if mpv < 0:
            logging.debug(
                "Negative MPV, collision was downwards (player on the ground)")
            max_y_o2 = o1.get_highest_point()

            player.place_at(player.x, max_y_o2 + player.get_height() // 2)
            player.in_the_air = False
            player.on_the_ground = True

        else:
            delta_e = 0
            if o1.nametype == "MovingPlatform":
                delta_e = abs(o1.y_speed * 3)
                logging.info(f"Adding a delta of {delta_e} to offset moving platform")
            min_y_o2 = o1.get_lowest_point() - delta_e
            player.place_at(player.x, min_y_o2 - player.get_height() // 2)

    @staticmethod
    def _align_x_edge(player, o1, mpv):
        player.x_speed = 0
        if player.y_sticky:
            player.y_speed = 0
        player.in_the_air = True
        player.on_the_ground = False

        logging.debug(mpv)
        if mpv > 0:
            logging.debug("Negative MPV, collision was right")
            min_x_o2 = o1.get_leftmost_point()
            player.x_speed = 0
            player.place_at(min_x_o2 - player.get_width() // 2 - 1, player.y)
        else:
            logging.debug("Positive MPV, collision was left")
            max_x_o2 = o1.get_rightmost_point()
            player.x_speed = 0
            player.place_at(max_x_o2 + player.get_width() // 2 + 1, player.y)
