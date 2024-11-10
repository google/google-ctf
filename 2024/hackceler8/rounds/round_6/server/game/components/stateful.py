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
import random

from game.engine import generics
from game.engine.keys import Keys
from game.engine.generics import hitbox


class StatefulObject(generics.GenericObject):
    def draw(self):
        self.draw()

    def __init__(self, coords, tileset_path, name, collectable=False):
        super().__init__(
            coords,
            nametype="Stateful",
            tileset_path=tileset_path,
            name=name,
            can_flip=True,
        )
        self.collectable = collectable
        self.collected = False
        self.game = None

    def tick(self):
        super().tick()


class Crops(StatefulObject):
    def __init__(self, coords):
        super().__init__(
            coords=coords,
            tileset_path="resources/objects/corn.png",
            name="crops"
        )
        self.cycle_point = 0
        self.growth_level = 0
        self.collectable = True
        self.soil = None
        self.game = None

    def check_collect(self):
        if self.collected:
            return
        if (not self.game.player.dead and
                self.expand(20).collides(self.game.player)):
            if Keys.T in self.game.newly_pressed_keys:
                if self.game.weather_system.season() == "Froznose":
                    self.game.display_textbox("You can't collect crops in the froznose!")
                    return
                self.collected = True
                self.game.stateful_inventory.append(self)

    def _update_animation(self, stage):
        if stage == "planted":
            self.load_sprite("resources/objects/weet.h8t")

    def tick(self):
        super().tick()
        self.check_collect()

    def grow(self):
        if not self.game or not self.game.weather_system:
            return

        if self.collected:
            return

        ws = self.game.weather_system

        if ws.snowing:
            self.cycle_point = max(0, self.cycle_point - 0.022)
            self.update_cycle()
            return

        if ws.hailing:
            if self.cycle_point > 0:
                logging.info("Oh no the crops got destroyed!!")
                self.cycle_point = 0
                self.update_cycle()
            return

        if ws.season() in ["Splashmelt", "Crispnap", "Blisterbake"]:
            if ws.raining:
                if ws.season() == "Splashmelt":
                    _growth = 0.4
                elif ws.season() == "Crispnap":
                    _growth = 0.2
                else:
                    _growth = 0.1
            else:
                if ws.season() == "Blisterbake":
                    _growth = 0.5
                elif ws.season() == "Crispnap":
                    _growth = 0.3
                else:
                    _growth = 0.1

            self.cycle_point += _growth

        self.update_cycle()

    def update_cycle(self):
        self.growth_level = int(round(self.cycle_point // 100, 0))
        self.sprite.scale = 1
        if self.growth_level < 2:
            self.sprite.set_animation("stage_0")
        elif self.growth_level < 5:
            self.sprite.set_animation("stage_1")
        else:
            self.sprite.set_animation("stage_2")
        # for i in range(self.growth_level):
        #     self.sprite.scale *= 2
        # logging.info(f"Set scale to {self.sprite.scale}")


class Soil(StatefulObject):
    def __init__(self, coords, **kwargs):
        super().__init__(
            coords=coords,
            name="soil",
            tileset_path=None,
        )
        self.is_planted = False
        self.total_nutrients = kwargs.get("nutrients", 0)
        self.crops = None
        self.interaction_cooldown = 0
        self.game = None

    def tick(self):
        super().tick()
        if self.interaction_cooldown:
            self.interaction_cooldown -= 1
        if self.crops:
            if self.total_nutrients:
                self.total_nutrients -= 1
                self.crops.grow()
            else:
                logging.info("Out of nutrients")
        self.interact()

    def interact(self):
        if self.interaction_cooldown:
            return
        if (not self.game.player.dead and
                self.expand(20).collides(self.game.player)):
            if Keys.T in self.game.newly_pressed_keys:
                if self.crops:
                    if self.game.weather_system.season() == "Froznose":
                        return
                    self.pick()
                else:
                    self.plant()

    def pick(self):
        self.interaction_cooldown = 3
        self.crops.collected = True
        self.crops = None

    def plant(self):
        self.interaction_cooldown = 3
        for it in self.game.stateful_inventory:
            if it.name == "crops":
                self.crops = it
                self.game.stateful_inventory.remove(it)
                self.game.objects.append(it)
                self.game.tiled_map.objects.append(it)
                self.game.physics_engine.add_generic_object(it)
                it.place_at(self.x + 20, self.y + 10)
                it.collected = False
                it._update_animation("planted")
                break


class WeatherSystem():
    SEASONS = ["Blisterbake", "Splashmelt", "Crispnap", "Froznose"]

    def __init__(self, name):
        self.ticks = 0
        self.game = None
        self.current_season = 0
        self.name = name
        self.snowing = False
        self.raining = False
        self.hailing = False
        self.rnd = random.Random()
        self.rnd.seed(self.name)

    def tick(self):
        self.ticks += 1
        if not self.ticks % 180:
            self.reset_weather()
            _r = self.rnd.randint(0, 10)
            if _r < 1:
                self.hailing = True
            elif _r < 3:
                self.snowing = True
            elif _r < 6:
                self.raining = True

        if not self.ticks % 720:
            self.current_season = (self.current_season + 1) % 4

    def season(self):
        return self.SEASONS[self.current_season]

    def reset_weather(self):
        self.snowing = False
        self.raining = False
        self.hailing = False
