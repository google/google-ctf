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

import arcade

from components.player import Player
from engine import generics
from engine import quadtree
from components.logic import PassiveLogicComponent

LOGIC_INTERVAL = 5

class LogicEngine:
    def __init__(self, logic_map):
        self.logic_map = logic_map
        self.logic_countdown = 0
        self.spritelist = arcade.SpriteList(lazy=True)
        for logic_id in self.logic_map:
            obj = self.logic_map[logic_id]
            if isinstance(obj, PassiveLogicComponent):
                self.spritelist.append(obj.sprite)

    def update_logic(self):
        outputs = {}
        for logic_id in self.logic_map:
            outputs[logic_id] = self.logic_map[logic_id].update_output()
        for logic_id in outputs:
            self.logic_map[logic_id].previous_output = outputs[logic_id]
            self.logic_map[logic_id].update_sprite()

    def tick(self):
        if self.logic_countdown == 0:
            self.update_logic()
            self.logic_countdown = LOGIC_INTERVAL
        self.logic_countdown -= 1

    def draw(self):
        self.spritelist.draw()
