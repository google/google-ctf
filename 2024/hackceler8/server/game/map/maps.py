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

from enum import Enum
from typing import NamedTuple, Optional

import os

from game.map import tilemap
from game.engine import gfx


class MapAttrs(NamedTuple):
    tiled_map: tilemap.TileMap

    def has_prerender(self) -> bool:
        prerender_path = self.tiled_map.file_path[:-4]+"_prerender.png"
        return os.path.exists(prerender_path)

    # do not call this multiple times, you will leak memory
    def prerender(self) -> Optional[gfx.SpriteLayer]:
        if not self.has_prerender():
            return None
        prerender_path = self.tiled_map.file_path[:-4] + "_prerender.png"
        img = gfx.load_image(prerender_path, 0, 0)
        layer = gfx.SpriteLayer()
        # correct for center coords
        if img.width is not None and img.height is not None:
          layer.add(gfx.SpriteDrawParams(img.width/2, img.height/2, img))
          layer.update_all_buffers()
        return layer


def load() -> dict[str, MapAttrs]:
  base_tilemap = tilemap.TileMap("resources/levels/base/base_level.h8m")

  beach_tilemap = tilemap.TileMap("resources/levels/beach/beach_lvl.h8m")

  ruins_tilemap = tilemap.TileMap("resources/levels/ruins/ruins_lvl.h8m")

  cloud_tilemap = tilemap.TileMap("resources/levels/cloud/cloud_lvl.h8m")

  ocean_tilemap = tilemap.TileMap("resources/levels/ocean/ocean_lvl.h8m")

  dialogue_boss_tilemap = tilemap.TileMap("resources/levels/boss/dialogue_boss.h8m")

  fighting_boss_tilemap = tilemap.TileMap("resources/levels/boss/fighting_boss.h8m")

  maps_dict = {
      "base": MapAttrs(base_tilemap),
      "beach": MapAttrs(beach_tilemap),
      "ruins": MapAttrs(ruins_tilemap),
      "cloud": MapAttrs(cloud_tilemap),
      "ocean": MapAttrs(ocean_tilemap),
      "dialogue_boss": MapAttrs(dialogue_boss_tilemap),
      "fighting_boss": MapAttrs(fighting_boss_tilemap),
  }

  return maps_dict
