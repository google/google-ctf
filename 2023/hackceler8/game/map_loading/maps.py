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

from enum import Enum

import arcade

from map_loading import tilemap


class GameMode(Enum):
    MODE_PLATFORMER = "platformer"
    MODE_SCROLLER = "scroller"


def load() -> dict:
    base_tilemap = tilemap.BasicTileMap("resources/maps/hackceler_map.tmx")
    base_scene = arcade.load_tilemap(
        "resources/maps/hackceler_map.tmx")

    cctv_tilemap = tilemap.BasicTileMap("resources/levels/cctv/cctv_level.tmx")
    cctv_scene = arcade.load_tilemap(
        "resources/levels/cctv/cctv_level.tmx")

    maps_dict = {
        "base": (base_tilemap, base_scene, GameMode.MODE_SCROLLER),
        "cctv": (cctv_tilemap, cctv_scene, GameMode.MODE_PLATFORMER),
        "rusty": (cctv_tilemap, cctv_scene, GameMode.MODE_PLATFORMER),
        "space": (cctv_tilemap, cctv_scene, GameMode.MODE_PLATFORMER),
        "water": (cctv_tilemap, cctv_scene, GameMode.MODE_PLATFORMER),
        "debug": (cctv_tilemap, cctv_scene, GameMode.MODE_PLATFORMER)
    }

    return maps_dict
