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
from typing import NamedTuple, Optional

from map_loading import tilemap
import arcade


class GameMode(Enum):
    MODE_PLATFORMER = "platformer"
    MODE_SCROLLER = "scroller"


class MapAttrs(NamedTuple):
    tiled_map: tilemap.BasicTileMap
    prerender: Optional[arcade.Texture]
    game_mode: GameMode


def load() -> dict:
    base_tilemap = tilemap.BasicTileMap("resources/maps/hackceler_map.tmx")

    spike_tilemap = tilemap.BasicTileMap("resources/maps/spike_map.tmx")

    cctv_tilemap = tilemap.BasicTileMap("resources/levels/cctv/cctv_level.tmx")
    cctv_prerender = arcade.load_texture("resources/levels/cctv/cctv_level.png")

    rusty_tilemap = tilemap.BasicTileMap("resources/levels/rusty/rusty_level.tmx")
    rusty_prerender = arcade.load_texture("resources/levels/rusty/rusty_level.png")

    space_tilemap = tilemap.BasicTileMap("resources/levels/space/space_level.tmx")
    space_prerender = arcade.load_texture("resources/levels/space/space_level.png")

    water_tilemap = tilemap.BasicTileMap("resources/levels/water/water_level.tmx")
    water_prerender = arcade.load_texture("resources/levels/water/water_level.png")

    danmaku_tilemap = tilemap.BasicTileMap("resources/maps/danmaku_map.tmx")

    maps_dict = {
        "base": MapAttrs(base_tilemap, None, GameMode.MODE_SCROLLER),
        "spike": MapAttrs(spike_tilemap, None, GameMode.MODE_SCROLLER),
        "danmaku": MapAttrs(danmaku_tilemap, None, GameMode.MODE_SCROLLER),
        "cctv": MapAttrs(cctv_tilemap, cctv_prerender, GameMode.MODE_PLATFORMER),
        "rusty": MapAttrs(rusty_tilemap, rusty_prerender, GameMode.MODE_PLATFORMER),
        "space": MapAttrs(space_tilemap, space_prerender, GameMode.MODE_PLATFORMER),
        "water": MapAttrs(water_tilemap, water_prerender, GameMode.MODE_PLATFORMER),
    }

    return maps_dict
