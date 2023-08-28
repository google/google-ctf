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
from pathlib import Path

import arcade
import pytiled_parser

import constants
from engine import animation

FLASH_DURATION_SECONDS = 0.1


def load_textures(tileset, can_flip, can_flash):
    # Two dimensions: textures[flipped][flashing]
    textures = {
        True: {True: None, False: None},
        False: {True: None, False: None},
    }
    for flipped in (False, True):
        for flashing in (False, True):
            # Load extra images only if they'll be used.
            if (flipped and not can_flip) or (flashing and not can_flash):
                textures[flipped][flashing] = None
            else:
                textures[flipped][flashing] = load_spritesheet(tileset, flipped,
                                                               flashing)
    return textures


def load_spritesheet(tileset, flipped: bool, flashing: bool):
    textures = []
    for y in range(tileset.tile_count // tileset.columns):
        for x in range(tileset.columns):
            logging.debug(f"loading {tileset.image}")
            texture = arcade.load_texture(file_name=tileset.image,
                                          x=x * tileset.tile_width,
                                          y=y * tileset.tile_height,
                                          width=tileset.tile_width,
                                          height=tileset.tile_height,
                                          flipped_horizontally=flipped)
            if flashing:
                # Turn non-transparent pixels white.
                img = texture.image.convert('RGBA')
                width, _ = img.size
                for i, px in enumerate(img.getdata()):
                    if px[3] > 0:
                        xx = i % width
                        yy = i // width
                        img.putpixel((xx, yy), (255, 255, 255, 255))
                texture = arcade.Texture(
                    name=f"{tileset.image},{x},{y},{flashing},{flipped}",
                    image=img)
            textures.append(texture)
    return textures


class Sprite:
    def __init__(self, tileset_path: str, can_flip=False, can_flash=False):
        self.flipped = False
        self.blinking = False
        self.flashing = False
        self.flash_time = 0
        self.tileset_path = tileset_path
        tileset = \
            list(pytiled_parser.parse_map(Path(self.tileset_path)).tilesets.values())[0]
        self.tiles = tileset.tiles
        self.textures = load_textures(tileset, can_flip, can_flash)

        self.animation = None
        self.scale = 1.0

    def tick(self):
        if self.animation is not None:
            self.animation.tick()
        if self.flashing:
            self.flash_time += constants.TICK_S
            if self.flash_time >= FLASH_DURATION_SECONDS:
                self.set_flashing(False)

    def draw(self, x, y):
        if self.animation is None:
            self.textures[self.flipped][self.flashing][0].draw_scaled(x, y, self.scale)
        else:
            self.animation.draw(x, y, self.scale)

    def set_animation(self, name):
        if self.animation is not None and name == self.animation.name:
            return
        self.animation = animation.Animation(name, self.blinking, self.tiles,
                                             self.textures[self.flipped][self.flashing])

    def set_flipped(self, flipped: bool):
        if flipped and self.textures[flipped][self.flashing] is None:
            logging.error(f"Flipping for {self} not configured")
            return

        self.flipped = flipped
        if self.animation is not None:
            self.animation.textures = self.textures[self.flipped][self.flashing]

    def set_blinking(self, blinking: bool):
        self.blinking = self.animation.blinking = blinking

    def set_flashing(self, flashing: bool):
        if flashing and self.textures[self.flipped][flashing] is None:
            logging.error(f"Flashing for {self} not configured")
            return

        self.flashing = flashing
        self.flash_time = 0
        if self.animation is not None:
            self.animation.textures = self.textures[self.flipped][self.flashing]

    def animation_finished(self) -> bool:
        return self.animation.finished()

    def get_dimensions(self) -> int:
        t = self.textures[self.flipped][self.flashing][0]
        return (t.width, t.height)
