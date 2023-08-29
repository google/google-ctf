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

GRAVITY_CONSTANT = 6
PLAYER_JUMP_SPEED = 320
PLAYER_MOVEMENT_SPEED = 160
PLAYER_RUN_SPEED = 50


class PhysicsEngine:
    def __init__(self,
                 gravity: int = GRAVITY_CONSTANT,
                 platformer_rules: bool  = True,
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

        self._reset_parameters()

        self.qt = qt
        self.platformer_rules = self.player.platformer_rules = platformer_rules
        if self.platformer_rules:
            self.player.load_sprite(Player.PLATFORMER_TILESET)
        self.debug_objs = []
        self.env_tiles = []
        self.tmp_loot = []
        self.exit_on_next = False

    def _reset_parameters(self):
        self.gravity, self.jump_speed, self.movement_speed, self.run_speed = self.original_params
        self.jump_override = False
        self.player.jump_override = self.jump_override
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
        self.player.update_position()
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

        if self.player.in_the_air:
            logging.debug("updating gravity speed for player")

            self.player.y_speed -= self.gravity

        for i in self.moving_platforms:
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

    def remove_generic_object(self, o):
        if o in self.objects:
            self.objects.remove(o)
        if o in self.static_objects:
            self.static_objects.remove(o)
        if o in self.moving_platforms:
            self.moving_platforms.remove(o)


    def _get_collisions_list(self):
        collisions_x, collisions_y, non_blocking = [], [], []
        for o1 in self.objects + self.static_objects + self.moving_platforms:
            c, mpv = o1.collides(self.player)
            if c:
                if o1.nametype in {"Item", "ExitArea", "Ouch", "Fire", "Arena"}:
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

    def _detect_collision(self):
        collisions_x, collisions_y, non_blocking = self._get_collisions_list()
        if len(collisions_x) + len(collisions_y) + len(non_blocking) == 0:
            self.player.in_the_air = True
            return
        for o, mpv in collisions_x:
            self._align_x_edge(o, mpv[0])

        _, collisions_y, non_blocking = self._get_collisions_list()
        logging.debug(f"There are {len(collisions_y)} collisions on the y axis")
        for o, mpv in collisions_y:
            self._align_y_edge(o, mpv[1])

        for n in non_blocking:
            logging.debug(f"Collision with {n.nametype}")
            match n.nametype:
                case "Item":
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

    def _align_y_edge(self, o1, mpv):
        self.player.y_speed = 0
        logging.debug(mpv)
        if mpv < 0:
            logging.debug(
                "Negative MPV, collision was downwards (player on the ground)")
            max_y_o2 = o1.get_highest_point()

            self.player.place_at(self.player.x, max_y_o2 +
                                 self.player.get_height() // 2)
            self.player.in_the_air = False
            self.player.on_the_ground = True

        else:
            logging.debug("Positive MPV, collision was upwards")
            min_y_o2 = o1.get_lowest_point()
            self.player.place_at(self.player.x, min_y_o2 -
                                 self.player.get_height() // 2)

    def _align_x_edge(self, o1, mpv):
        self.player.x_speed = 0
        self.player.in_the_air = True
        self.player.on_the_ground = False

        logging.debug(mpv)
        if mpv > 0:
            logging.debug("Negative MPV, collision was right")
            min_x_o2 = o1.get_leftmost_point()
            self.player.x_speed = 0
            self.player.place_at(min_x_o2 - self.player.get_width() // 2 - 1,
                                 self.player.y)
        else:
            logging.debug("Positive MPV, collision was left")
            max_x_o2 = o1.get_rightmost_point()
            self.player.x_speed = 0
            self.player.place_at(max_x_o2 + self.player.get_width() // 2 + 1,
                                 self.player.y)
