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

from engine import generics
from engine import hitbox
import constants

class Npc(generics.GenericObject):
    WALK_SPEED = 100  # 100 pixels per second
    DIR_N = "N"
    DIR_E = "E"
    DIR_S = "S"
    DIR_W = "W"

    def __init__(self, coords, name, walk_data, scale, tileset_path):
        super().__init__(coords, nametype="NPC", tileset_path=tileset_path,
                         name=name, can_flash=True)
        self.walk_data = self._load_walk_data(walk_data)
        self.walk_progress = 0
        # Will be overwritten
        self.display_textbox = lambda _x: logging.fatal("Npc.display_textbox not set")
        self.blocking = True
        self.should_move = True
        self.sprite.set_animation("idle-front")
        self.sprite.scale = scale
        w, h = self.sprite.get_dimensions()
        outline = [
            hitbox.Point(coords.x - w * scale / 2, coords.y - h * scale / 2),
            hitbox.Point(coords.x + w * scale / 2, coords.y - h * scale / 2),
            hitbox.Point(coords.x + w * scale / 2, coords.y + h * scale / 2),
            hitbox.Point(coords.x - w * scale / 2, coords.y + h * scale / 2),
        ]
        self._update(outline)

    def _load_walk_data(self, data_str):
        if len(data_str) == 0:
            return []

        # Load the walking pattern of the NPC from a string
        # e.g. N100,E100: Walk 100px north, then 100px east.
        result = []
        direction = None
        for d in data_str.split(","):
            match d[0]:
                case "N":  # Move north N px
                    direction = self.DIR_N
                case "E":  # Move east N px
                    direction = self.DIR_E
                case "S":  # Move south N px
                    direction = self.DIR_S
                case "W":  # Move west N px
                    direction = self.DIR_W
                case _:
                    result.append(int(d))  # Sleep for N ms
                    continue
            result.append((direction, int(d[1:])))
        return result

    def _get_walk_duration(self, walk_step):
        if not isinstance(walk_step, tuple):  # Sleep for N ms
            return walk_step / 1000
        # Move N px
        px = walk_step[1]
        return px / self.WALK_SPEED

    def _walk(self, walk_step, dur):
        if not isinstance(walk_step, tuple):
            # Stand still
            direction = self.sprite.animation.name.split("-")[1]
            self.sprite.set_animation(f"idle-{direction}")
            return
        # Walk
        dist = dur * self.WALK_SPEED
        match walk_step[0]:
            case "N":
                self.move(0, dist)
                self.sprite.set_animation("walk-back")
            case "E":
                self.move(dist, 0)
                self.sprite.set_animation("walk-right")
            case "S":
                self.move(0, -dist)
                self.sprite.set_animation("walk-front")
            case "W":
                self.move(-dist, 0)
                self.sprite.set_animation("walk-left")

    def stop_moving(self, x, y):
        # Only stop moving if walking towards the player
        if ((self.prev_x < self.x and x > self.x) or
            (self.prev_x > self.x and x < self.x) or
            (self.prev_y < self.y and y > self.y) or
            (self.prev_y > self.y and y < self.y)):
            self.should_move = False

    def resume_moving(self):
        self.should_move = True

    def turn_to_player(self, x, y):
        rect = self.get_rect()
        if x >= rect.x2:
            self.sprite.set_animation("idle-right")
        elif y >= rect.y2:
            self.sprite.set_animation("idle-back")
        elif x <= rect.x1:
            self.sprite.set_animation("idle-left")
        else:
            self.sprite.set_animation("idle-front")

    def tick(self):
        super().tick()
        if len(self.walk_data) == 0 or not self.should_move:
            direction = self.sprite.animation.name.split("-")[1]
            self.sprite.set_animation(f"idle-{direction}")
            return

        # Walk around: First find the current walk step
        i = 0
        progress = self.walk_progress
        while True:
            dur = self._get_walk_duration(self.walk_data[i])
            if progress <= dur:
                break
            progress -= dur
            i += 1
            if i >= len(self.walk_data):  # Loops
                i = 0
                self.walk_progress -= sum(
                    [self._get_walk_duration(w) for w in self.walk_data])
        # Then progress the current step (and possibly next ones).
        delta = constants.TICK_S
        while True:
            dur = self._get_walk_duration(self.walk_data[i]) - progress
            if delta <= dur:
                self._walk(self.walk_data[i], delta)
                break
            self._walk(self.walk_data[i], dur)
            progress = 0
            delta -= dur
            i = (i + 1) % len(self.walk_data)  # Loops
        self.walk_progress += constants.TICK_S


class PasswordNpc(Npc):  # An NPC that asks for a password
    def __init__(self, coords, name, walk_data):
        super().__init__(coords, name, walk_data, scale=1,
                         tileset_path="resources/NPCs/Snake_NPC.tmx")
        self.sprite.set_animation("walk-front")

    def dialogue(self):
        text = "Psssst! Do you know the passssword?"

        def yes():
            self.display_textbox("Then dissssclose it to me!", free_text_fun=password_check)

        def no():
            self.display_textbox("Oh, that'sssss a shame.")

        def password_check(password: str):
            if password == "hunter1":
                self.display_textbox("Yep, that'sssss correct!")
            else:
                self.display_textbox("No, that'sssss not it.")

        self.display_textbox(text, choices=[("YES", yes), ("NO", no)])


class BarkNpc(Npc):  # An NPC that can only say one thing
    def __init__(self, coords, name, walk_data):
        super().__init__(coords, name, walk_data, scale=2,
                         tileset_path="resources/NPCs/Dog_NPC.tmx")

    def dialogue(self):
        self.display_textbox("BARK BARK!")


NPC_TYPES = {"password_npc": PasswordNpc, "bark_npc": BarkNpc}
