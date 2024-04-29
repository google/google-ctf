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

def load_debug() -> dict:
    debug_tilemap = tilemap.BasicTileMap("resources/levels/cctv/cctv_level.tmx")
    # Can be None
    debug_prerender = arcade.load_texture("resources/levels/cctv/cctv_level.png")
    debug_map = MapAttrs(debug_tilemap, debug_prerender, GameMode.MODE_PLATFORMER)

    base_tilemap = tilemap.BasicTileMap("resources/maps/hackceler_map.tmx")

    spike_tilemap = tilemap.BasicTileMap("resources/maps/spike_map.tmx")

    speed_tilemap = tilemap.BasicTileMap("resources/maps/speed_map.tmx")

    logic_tilemap = tilemap.BasicTileMap("resources/maps/logic_map.tmx")

    boss_tilemap = tilemap.BasicTileMap("resources/maps/boss_map.tmx")

    danmaku_tilemap = tilemap.BasicTileMap("resources/maps/danmaku_map.tmx")

    maps_dict = {
        "base": MapAttrs(base_tilemap, None, GameMode.MODE_SCROLLER),
        "spike": MapAttrs(spike_tilemap, None, GameMode.MODE_SCROLLER),
        "speed": MapAttrs(speed_tilemap, None, GameMode.MODE_SCROLLER),
        "logic": MapAttrs(logic_tilemap, None, GameMode.MODE_SCROLLER),
        "danmaku": MapAttrs(danmaku_tilemap, None, GameMode.MODE_SCROLLER),
        "boss": MapAttrs(boss_tilemap, None, GameMode.MODE_SCROLLER),
        "cctv": debug_map,
        "rusty": debug_map,
        "space": debug_map,
        "water": debug_map,
        "debug": debug_map,
    }

    return maps_dict

def load() -> dict:
    base_tilemap = tilemap.BasicTileMap("resources/maps/hackceler_map.tmx")

    spike_tilemap = tilemap.BasicTileMap("resources/maps/spike_map.tmx")

    speed_tilemap = tilemap.BasicTileMap("resources/maps/speed_map.tmx")

    logic_tilemap = tilemap.BasicTileMap("resources/maps/logic_map.tmx")

    boss_tilemap = tilemap.BasicTileMap("resources/maps/boss_map.tmx")

    cctv_tilemap = tilemap.BasicTileMap("resources/levels/cctv/cctv_level.tmx")
    cctv_prerender = arcade.load_texture("resources/levels/cctv/cctv_level.png")

    rusty_tilemap = tilemap.BasicTileMap("resources/levels/rusty/rusty_level.tmx")
    rusty_prerender = arcade.load_texture("resources/levels/rusty/rusty_level.png")

    space_tilemap = tilemap.BasicTileMap("resources/levels/space/space_level.tmx")

    water_tilemap = tilemap.BasicTileMap("resources/levels/water/water_level.tmx")

    debug_tilemap = tilemap.BasicTileMap("resources/levels/debug/debug_level.tmx")

    danmaku_tilemap = tilemap.BasicTileMap("resources/maps/danmaku_map.tmx")

    maps_dict = {
        "base": MapAttrs(base_tilemap, None, GameMode.MODE_SCROLLER),
        "spike": MapAttrs(spike_tilemap, None, GameMode.MODE_SCROLLER),
        "speed": MapAttrs(speed_tilemap, None, GameMode.MODE_SCROLLER),
        "logic": MapAttrs(logic_tilemap, None, GameMode.MODE_SCROLLER),
        "danmaku": MapAttrs(danmaku_tilemap, None, GameMode.MODE_SCROLLER),
        "boss": MapAttrs(boss_tilemap, None, GameMode.MODE_SCROLLER),
        "cctv": MapAttrs(cctv_tilemap, cctv_prerender, GameMode.MODE_PLATFORMER),
        "rusty": MapAttrs(rusty_tilemap, rusty_prerender, GameMode.MODE_PLATFORMER),
        "space": MapAttrs(space_tilemap, None, GameMode.MODE_PLATFORMER),
        "water": MapAttrs(water_tilemap, None, GameMode.MODE_PLATFORMER),
        "debug": MapAttrs(debug_tilemap, None, GameMode.MODE_PLATFORMER),
    }

    return maps_dict
