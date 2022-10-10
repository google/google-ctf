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

from typing import Optional, Union

import map_loader
from gametree import Component, Entity, Frameset
import environ
import utils
import serialize
import sprites


def _ancestor_object_layer(entity: Entity):
    while entity is not None:
        layer = entity.get_component(map_loader.ObjectLayer)
        if layer:
            return layer
        entity = entity.parent


class Renderer(Component):
    _sprite = serialize.Unserialized()
    _in_sprite_list: bool = serialize.Unserialized()

    def __init__(self, sprite: Optional[sprites.Sprite] = None):
        super().__init__()
        self.sprite = sprite
        self._in_sprite_list = False

    @property
    def sprite(self) -> Optional[Union[sprites.Sprite, sprites.MultiSprite]]:
        return self._sprite

    @sprite.setter
    def sprite(self, value: Union[sprites.Sprite, sprites.MultiSprite]):
        if self._sprite:
            self._remove_from_sprite_list()

        self._sprite = value

    def tick(self):
        super().tick()
        if self.sprite:
            self.sprite.tick()
            if not self._in_sprite_list:
                self._add_to_sprite_list()

    def update_sprite(self):
        if self.sprite:
            self.entity.transform.transform_sprite(self.sprite)

    @environ.client_only
    def draw(self):
        self.update_sprite()
        if self.sprite:
            self.sprite.draw(filter=environ.arcade.gl.gl.GL_NEAREST, pixelated=True)

    def added(self):
        super().added()
        if self.sprite is not None:
            self._remove_from_sprite_list()
            self._in_sprite_list = False

    def entity_removed(self, old_parent):
        if self.sprite is not None:
            self._remove_from_sprite_list(start_at=old_parent)
            self._in_sprite_list = False

    @environ.client_only_or(None)
    def _add_to_sprite_list(self):
        layer = _ancestor_object_layer(self.entity)
        if layer:
            layer.sprite_list.append(self.sprite)
            self._in_sprite_list = True

    @environ.client_only_or(None)
    def _remove_from_sprite_list(self, start_at=None):
        if start_at is None:
            start_at = self.entity
        layer = _ancestor_object_layer(start_at)
        if layer is not None and self._in_sprite_list:
            layer.sprite_list.remove(self.sprite)
            self._in_sprite_list = False

    def init_unserialized(self, deserializer):
        self._sprite = None
        self._in_sprite_list = False


class SingleRenderer(Renderer):
    def __init__(self, tmx_data=None, tileset_name: str =None, relative_gid: int =None):
        """Must provide either tmx_data or (tileset_name and relative_gid)."""
        if tmx_data is not None:
            self.tileset_name, self.relative_gid = environ.game.gid_to_tile_reference(tmx_data.gid)
        if tileset_name is not None:
            self.tileset_name = tileset_name
        if relative_gid is not None:
            self.relative_gid = relative_gid

        if environ.environ == "client":
            sprite = environ.game.make_sprite(environ.game.get_tile_by_tile_reference(self.tileset_name, self.relative_gid))
            super().__init__(sprite)
        else:
            super().__init__()

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)
        if environ.environ == "client":
            self.sprite = deserializer.context.make_sprite(deserializer.context.get_tile_by_tile_reference(self.tileset_name, self.relative_gid))

    def duplicate(self, new_entity):
        new_component = self.__class__(tileset_name=self.tileset_name, relative_gid=self.relative_gid)
        return new_component


class MultiRenderer(Renderer):
    def on_frameset_changed(self, new_frameset):
        if self.sprite:
            self.sprite.set_frameset(new_frameset)

    def added(self):
        super().added()
        self.on_framesets_changed(self.entity.framesets, environ.game)

    def on_framesets_changed(self, framesets: dict[str, Frameset], game):
        super().on_framesets_changed(framesets, game)

        if not environ.environ == "client":
            return

        flipped_horizontally = utils.is_flipped_horizontally(self.entity.gid)
        flipped_vertically = utils.is_flipped_vertically(self.entity.gid)
        self.sprite = game.make_multi_sprite(
            framesets, flipped_horizontally=flipped_horizontally, flipped_vertically=flipped_vertically)

#    def post_deserialize(self, deserializer):
#        self.on_framesets_changed(self.framesets)
#        self.on_frameset_changed(self.frameset)

    def duplicate(self, new_entity):
        # Framesets get set when the renderer is attached to the entity
        new_component = self.__class__()
        return new_component