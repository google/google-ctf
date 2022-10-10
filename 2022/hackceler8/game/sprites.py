# Copyright 2022 Google LLC
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

from typing import Optional
import bisect
import itertools
import sys

import arcade
import pytiled_parser


class Timekeeper:
    """We keep time in frames, but Tiled keeps time in milliseconds.
    This class maintains a correct, float-free conversion."""
    def __init__(self, start_frame: int = 0, loop_ms:int = sys.maxsize):
        self.frame = start_frame
        self.loop_ms = loop_ms

    def tick(self) -> None:
        self.frame += 1

    @property
    def elapsed_time_ms(self) -> int:
        mod = self.frame % 3
        if mod == 0:
            ret = (self.frame * 1000) // 60
        elif mod == 1:
            ret = 1 + (self.frame * 1000) // 60
        else: # mod == 2:
            ret = (self.frame * 1000) // 60
        return ret % self.loop_ms


class Sprite(arcade.AnimatedTimeBasedSprite):
    """A sprite that is flippable."""

    def __init__(
        self,
        filename: str,
        tile: pytiled_parser.Tile,
        scale: float = 1,
        image_x: float = 0,
        image_y: float = 0,
        image_width: float = 0,
        image_height: float = 0,
        center_x: float = 0,
        center_y: float = 0,
        repeat_count_x: int = 1,  # Unused
        repeat_count_y: int = 1,  # Unused
        flipped_horizontally: bool = False,
        flipped_vertically: bool = False,
        flipped_diagonally: bool = False,
        hit_box_algorithm: str = "None",
        hit_box_detail: float = 4.5,
        angle: float = 0,
    ):
        self._texture_: Optional[arcade.Texture] = None
        if hit_box_algorithm != "None":
            sys.stderr.write(f"Constructed sprite with hit_box_algorithm == {hit_box_algorithm}; computed hitboxes are not supported.")
        self.sprite_lists = []
        arcade.Sprite.__init__(
            self,
            filename,
            scale,
            image_x,
            image_y,
            image_width,
            image_height,
            center_x,
            center_y,
            repeat_count_x,
            repeat_count_y,
            flipped_horizontally,
            flipped_vertically,
            flipped_diagonally,
            hit_box_algorithm,
            hit_box_detail,
            None,
            angle)

        self.tile = tile

        self._frames: list[arcade.AnimationKeyframe] = []

        if tile.animation is None:
            self.textures = self._load_textures(filename, image_x, image_y, image_width, image_height,
                                                flipped_horizontally, flipped_vertically, flipped_diagonally)
            self._frames = [arcade.AnimationKeyframe(tile.id, 0, self.textures[0])]
            self._texture = self.textures[0]
            self.animated = False
            return

        # Arcade doesn't pass along tile-flip settings for animated sprites. It would be better to patch arcade for
        # this, but to minimize the amount of weird dependencies, just correct that here.
        flipped_horizontally = tile.flipped_horizontally
        flipped_vertically = tile.flipped_vertically

        self.textures = []
        for frame in tile.animation:
            x, y, width, height = self._get_image_info_from_tileset(tile.tileset, frame.tile_id)
            textures = self._load_textures(filename, x, y, width, height, flipped_horizontally, flipped_vertically, flipped_diagonally)
            self._frames.append(arcade.AnimationKeyframe(frame.tile_id, frame.duration, textures[0]))
            self.textures.extend(textures)
            self.animated = True

        self._texture = self.textures[0]

        self._progress_ms_to_frame = []
        accum = 0
        for frame in self.frames:
            self._progress_ms_to_frame.append(accum)
            accum += frame.duration
        self._timekeeper: Timekeeper = Timekeeper(loop_ms=accum)

    @property
    def frames(self) -> list[arcade.AnimationKeyframe]:
        return self._frames

    @frames.setter
    def frames(self, value: list[arcade.AnimationKeyframe]) -> None:
        # Hack to defeat pytiled_parser's attempt to overwrite .frame
        return

    @property
    def _texture(self) -> Optional[arcade.Texture]:
        return self._texture_

    @_texture.setter
    def _texture(self, value: arcade.Texture):
        if value == self._texture_:
            return

        self._texture_ = value
        self._point_list_cache = None

        for sprite_list in self.sprite_lists:
            sprite_list.update_texture(self)

    def tick(self):
        if self.animated:
            self._timekeeper.tick()
            ms = self._timekeeper.elapsed_time_ms
            idx = bisect.bisect_left(self._progress_ms_to_frame, ms) - 1
            frame = self.frames[idx]
            self._texture = frame.texture

    def draw(self, *args, **kwargs):
        self.tick()
        super().draw(*args, **kwargs)

    def _load_textures(self, filename, image_x, image_y, image_width, image_height, flipped_horizontally, flipped_vertically, flipped_diagonally) -> list[arcade.Texture]:
        textures: list[Optional[arcade.Texture]] = [None] * 4

        for horizontal_flip, vertical_flip in itertools.product(range(0, 2), range(0, 4, 2)):
            texture = arcade.load_texture(
                filename,
                image_x,
                image_y,
                image_width,
                image_height,
                flipped_horizontally=flipped_horizontally != bool(horizontal_flip),
                flipped_vertically=flipped_vertically != bool(vertical_flip),
                flipped_diagonally=flipped_diagonally,
            )
            texture.image_coords = (image_x, image_y)
            textures[horizontal_flip + vertical_flip] = texture
        return textures

    def update_animation(self, delta_time: float = 1/60):
        pass

    def _get_image_info_from_tileset(self, tileset: pytiled_parser.Tileset, tile_id: int) -> tuple[int, int, int, int]:
        image_x = 0
        image_y = 0
        if tileset.image is not None:
            margin = tileset.margin or 0
            spacing = tileset.spacing or 0
            row = tile_id // tileset.columns
            image_y = margin + row * (tileset.tile_height + spacing)
            col = tile_id % tileset.columns
            image_x = margin + col * (tileset.tile_width + spacing)

        if tileset.image:
            width = tileset.tile_width
            height = tileset.tile_height
        else:
            width = tileset.image_width
            height = tileset.image_height

        return image_x, image_y, width, height


class MultiSprite(Sprite):
    def __init__(self, sprites: dict[str, Sprite]):
        self._texture_: Optional[arcade.Texture] = None
        self.sprites = sprites

        """if "" in sprites:
            self.sprite = sprites[""]
        else:
            self.sprite = list(sprites.values())[0]
        self._texture_: arcade.Texture = self.sprite._texture
        
        arcade.Sprite.__init__(self, image_width=self._texture_.width, image_height=self._texture_.height,
                               center_x=self.sprite.center_x, center_y=self.sprite.center_y)"""
        self.sprite_lists = []
        arcade.Sprite.__init__(self, hit_box_algorithm=None)  # Notice that this is arcade.Sprite and not Sprite

        self.textures = []
        self.textures_by_frameset_offset = {}
        for frameset, sprite in self.sprites.items():
            self.textures_by_frameset_offset[frameset] = len(self.textures)
            self.textures.extend(sprite.textures)

        self.set_frameset(list(sprites.keys())[0])

    def set_frameset(self, frameset: str):
        self.frameset = frameset
        self.sprite = self.sprites[frameset]
        self.animated = self.sprite.animated
        self._texture = self.sprite.textures[0]

        if self.animated:
            self._timekeeper: Timekeeper = Timekeeper(loop_ms=self.sprite._timekeeper.loop_ms)
            self._progress_ms_to_frame = self.sprite._progress_ms_to_frame
            self._frames = self.sprite.frames
        else:
            if hasattr(self, "_timekeeper"):
                del self._timekeeper

    def set_texture(self, texture_no: int):
        if self.animated:
            return  # TODO: implement. This is used for mirroring and such.

        super().set_texture(texture_no + self.textures_by_frameset_offset[self.frameset])

