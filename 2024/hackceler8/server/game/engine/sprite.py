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
from typing import Optional, Dict, Tuple, Iterable
import logging

import json
import os
from typing import Any, List

from game import constants
from game.engine import animation
from game.engine import gfx
from game.map.tileset import  Tileset
from PIL import Image

from game.engine.animation import Animation

FLASH_DURATION_SECONDS = 0.1


def _load_tileset(tileset_path: str) -> Tileset:
  ts = Tileset()
  if tileset_path.endswith(".h8t"):
    ts.load(tileset_path)
    cwd = os.path.dirname(os.path.realpath(tileset_path))
    ts.image =  os.path.join(cwd, ts.image)
  else: # Tileset is a one-tile image
    with Image.open(tileset_path) as f:
      w = f.width
      h = f.height
    ts.tw = w
    ts.th = h
    ts.w = ts.h = 1
    ts.image = tileset_path
  return ts


def _load_textures(tileset, can_flip: bool) -> dict[bool, Optional[list[gfx.TextureReference]]]:

  textures: dict[bool, Optional[list[gfx.TextureReference]]] = {
      True: None,
      False: None,
  }
  for flipped in (False, True):
    # Load extra images only if they'll be used.
    if flipped and not can_flip:
      textures[flipped] = None
    else:
      textures[flipped] = load_spritesheet(
          tileset, flipped
      )
  return textures


def load_spritesheet(tileset, flipped: bool) -> list[gfx.TextureReference]:
  textures = []
  for y in range(tileset.h):
    for x in range(tileset.w):
      texture = gfx.load_image(
        tileset.image,
        x=x * tileset.tw,
        y=(tileset.h*tileset.th) - (y+1) * tileset.th,
        w=tileset.tw,
        h=tileset.th,
        flip_h=flipped
      )

      textures.append(texture)
  return textures


class Sprite:

  def __init__(
      self, tileset_path: str, can_flip=False,
  ):
    self.can_flip = can_flip
    self.flipped = False
    self.blinking = False
    self.flashing = False
    self.flash_time = 0
    self.max_flash_time = FLASH_DURATION_SECONDS
    self.tileset = _load_tileset(tileset_path)
    self.textures = _load_textures(self.tileset, self.can_flip)

    self.animation: Optional[Animation] = None
    self.scale = 1.0
    self.alpha = 255

  def tick(self):
    if self.animation is not None:
      self.animation.tick()
    if self.flashing:
      self.flash_time += constants.TICK_S
      if self.flash_time >= self.max_flash_time:
        self.set_flashing(False)

  def get_draw_info(self, x, y) -> gfx.IterableParams:
    if self.animation is None:
      return [gfx.SpriteDrawParams(flashing=self.flashing, x=x, y=y, scale=self.scale, alpha=self.alpha,
                                   tex=self.textures[self.flipped][0])]
    else:
      return self.animation.get_draw_info(x, y, self.scale, alpha=self.alpha)

  def set_animation(self, name):
    if self.animation is not None and name == self.animation.name:
      return
    self.animation = animation.Animation(
        name,
        self.blinking,
        self.flashing,
        self.tileset,
        self.textures[self.flipped],
    )

  def get_animation(self):
    if self.animation is None:
      return ""
    return self.animation.name

  def has_animation(self, name):
    for a in self.tileset.anims:
      if a["name"] == name:
        return True
    return False

  def set_texture(self, img_path):
    if not os.path.isfile(img_path):
      logging.error(f"Couldn't find texture image {img_path}")
      return
    self.tileset = _load_tileset(img_path)
    self.textures = _load_textures(self.tileset, self.can_flip)

    # Refresh animation.
    if self.animation is None:
      return
    name = self.animation.name
    self.animation = None
    self.set_animation(name)

  def set_flipped(self, flipped: bool):
    if flipped and self.textures[flipped] is None:
      logging.error(f"Flipping for {self} not configured")
      return

    self.flipped = flipped
    if self.animation is not None:
      self.animation.textures = self.textures[self.flipped]

  def set_blinking(self, blinking: bool):
    assert self.animation is not None
    self.blinking = self.animation.blinking = blinking

  def set_flashing(self, flashing: bool, flash_time=FLASH_DURATION_SECONDS):
      self.flashing = flashing
      self.flash_time = 0
      self.max_flash_time = flash_time
      if self.animation is not None:
          self.animation.flashing = flashing

  def animation_finished(self) -> bool:
      assert self.animation is not None
      return self.animation.finished()

  def get_dimensions(self) -> Tuple[int, int]:
      t = self.textures[self.flipped][0]
      return (t.width, t.height)
