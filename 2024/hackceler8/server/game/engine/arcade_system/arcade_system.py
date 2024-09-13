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
import os
import subprocess

from game import constants
from game.components import items
from game.components.items import check_item_loaded
from subprocess import Popen, PIPE
import numpy as np
from game.engine.keys import Keys

from game.engine import gfx


class ArcadeSystem:
    TILESET_W = 8
    TILESET_H = 8
    MAX_TILE_ID = 64
    IMG = "resources/objects/arcade_tiles.png"
    ITEM = items.Item(coords=None, name="key", display_name="Key")
    won = False

    def __init__(self, game):
        logging.info("Initiating arcade system")
        self.game = game
        self.proc = None
        self.bg = None
        self.layer = None
        self.atlas = None
        self.camera = None
        if check_item_loaded(self.game.items, self.ITEM):
            ArcadeSystem.won = True
        try:
            self.proc = Popen(os.path.join(os.getcwd(), "game/engine/arcade_system/game"), stdin=PIPE, stdout=PIPE)
        except Exception as e:
            logging.critical(f"Failed to initialize arcade: {str(e)}")

        self.w = int.from_bytes(self.proc.stdout.read(1))
        self.h = int.from_bytes(self.proc.stdout.read(1))
        self.tw = int.from_bytes(self.proc.stdout.read(1))
        self.th = int.from_bytes(self.proc.stdout.read(1))
        self.startX = (constants.SCREEN_WIDTH - self.w * self.tw) * 0.5
        self.startY = (constants.SCREEN_HEIGHT - self.h * self.th) * 0.5

    def load(self):
        refs = []
        for tileID in range(self.MAX_TILE_ID):
            refs.append(self.atlas.load(
                path=gfx._resolve_path(self.IMG),
                x=(tileID % self.TILESET_W) * self.tw,
                y=(self.TILESET_H * self.th) - ((tileID // self.TILESET_H)+1) * self.th,
                w=self.tw, h=self.th,
            ))

        assert list(range(self.MAX_TILE_ID)) == [i.region_id for i in refs]
        self.atlas.maybe_build()
        for y in range(self.h):
            for x in range(self.w):
                self.layer.add(gfx.SpriteDrawParams(
                    x=self.startX + (x + 0.5) * self.tw,
                    y=self.startY + (y + 0.5) * self.th,
                    alpha=255,
                    tex=refs[0]
                ))
        self.layer.update_all_buffers()

    def close(self):
        if self.proc is not None:
            self.proc.kill()
            self.proc = None

    def tick(self):
        if Keys.ESCAPE in self.game.newly_pressed_keys:
            self.game.close_arcade_system()
            return
        if self.proc is None:
            return

        keys_str = "%d" % (Keys.W in self.game.pressed_keys)
        keys_str += "%d" % (Keys.A in self.game.pressed_keys)
        keys_str += "%d" % (Keys.S in self.game.pressed_keys)
        keys_str += "%d" % (Keys.D in self.game.pressed_keys)
        keys_str += "%d" % (Keys.SPACE in self.game.pressed_keys)
        try:
            self.proc.stdin.write(str.encode("TICK %s\n" % keys_str))
            self.proc.stdin.flush()
            win_state = self.proc.stdout.read(1)
        except Exception as e:
            logging.exception(e)
            logging.info("Arcade process exited")
            self.game.close_arcade_system()
            return
        if win_state == b'W':
            if not ArcadeSystem.won:
                ArcadeSystem.won = True
                if self.ITEM is not None:
                    self.game.gather_item(self.ITEM)
            self.game.close_arcade_system()

    def draw(self):
        if self.bg is None:
            self.bg = gfx.ShapeLayer()
            self.layer = gfx.SpriteLayer()
            self.atlas = gfx.TextureAtlas(size=512, id_base=0)
            self.camera = gfx.Camera(constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT)
            self.camera.update()
            self.load()

        self.bg.clear()
        self.bg.add(gfx.lrtb_rectangle_filled(
            0, constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT, 0,
            (211, 211, 211, 255),
        ))
        self.bg.add(gfx.lrtb_rectangle_filled(
            self.startX, self.startX + self.w * self.tw, self.startY + self.h * self.th, self.startY,
            (255, 255, 255, 255),
        ))
        self.bg.build()
        self.bg.draw()

        if self.proc is None:
            self._draw_tiles()
            return

        try:
            self.proc.stdin.write(b"DRAW\n")
            self.proc.stdin.flush()
        except:
            self._draw_tiles()
            return

        try:
            buf = np.frombuffer(self.proc.stdout.read(self.h * self.w), dtype=np.uint8)
        except subprocess.SubprocessError:
            logging.info("Arcade process exited")
            self.game.close_arcade_system()
            self._draw_tiles()
            return
        assert all(i < self.MAX_TILE_ID for i in buf)
        # The sprite shader wants a buffer of indexes into the sprite descriptor SSBO. We never _move_ the sprite
        # positions here, just change their textures, so we can Simply push the entire index buffer to the gpu.
        self.layer.txs_buffer.write(buf.astype(np.uint32).tobytes())
        self._draw_tiles()

    def _draw_tiles(self):
        self.camera.use()
        self.layer.draw_all_cached()
