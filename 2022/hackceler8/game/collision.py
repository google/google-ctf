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

import pytiled_parser

import serialize
from gametree import Component, Vector2f, Vector2
import environ
import utils
import numpy as np
import math
from typing import Optional
import sys

from shapely import speedups  # type: ignore
from shapely.geometry import Polygon, Point  # type: ignore
from shapely.ops import nearest_points

_PRECISION = 2
COLLIDER_DRAW_COLOR = (76, 40, 130, 127)

speedups.enable()


class Collider(Component):
    colliders = serialize.Unserialized()
    _transformed_colliders = serialize.Unserialized()
    _transformed_collider_polygons = serialize.Unserialized()
    _transformed_updated = serialize.Unserialized()

    def __init__(self):
        super().__init__()
        self.colliders: Optional[list] = None

        self._transformed_colliders: Optional[list] = None
        self._transformed_collider_polygons: Optional[list[Polygon]] = None
        self._transformed_updated: int = -1
        self.solid: bool = True

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)
        self._init_unserialized_called = True
        self._transformed_colliders = None
        self._transformed_collider_polygons = None
        self._transformed_updated = -1

    def duplicate(self, new_entity):
        new_component = self.__class__()
        new_component.colliders = self.colliders
        new_component.solid = self.solid
        return new_component

    def test_intersection(self, other) -> bool:
        if self.colliders is None:
            return False
        try:
            for left_c, left_p in zip(self.transformed_colliders, self.transformed_collider_polygons):
                for right in other.get_pcolliders(left_c):
                    if are_polygons_intersecting(left_p, right):
                        return True
        except TypeError as e:
            sys.stderr.write(str(e) + "\n")
        return False

    def _update_transformed_colliders(self):
        if self._transformed_updated < self.entity.transform_modified:
            self._transformed_colliders = None
            self._transformed_collider_polygons = None

        if self._transformed_colliders is None:
            self._transformed_colliders = [self.entity.transform.transform_points(c) for c in self.colliders]
            self._transformed_collider_polygons = [
                Polygon(c) for c in self._transformed_colliders]
            self._transformed_updated = environ.game.get_modification_stamp()

    @property
    def transformed_colliders(self) -> Optional[list]:
        self._update_transformed_colliders()
        return self._transformed_colliders

    @property
    def transformed_collider_polygons(self) -> Optional[list]:
        self._update_transformed_colliders()
        return self._transformed_collider_polygons

    def minimum_translation_vector(self, other) -> Optional[Vector2]:
        ret = Vector2f()
        for left in self.colliders:
            left_t = self.entity.transform.transform_points(left)
            for right in other.get_colliders(left_t):
                right_t = other.entity.transform.transform_points(right)
                mtv = minimum_translation_vector(
                    left_t,
                    right_t)
                if mtv is not None:
                    ret += mtv
        if ret[0] == 0.0 and ret[1] == 0.0:
            return None
        return ret

    def get_colliders(self, other_collider) -> list:
        if self.colliders is None:
            raise RuntimeError(f"Colliders are not set!")
        return self.colliders

    def get_pcolliders(self, other_collider) -> list:
        return self.transformed_collider_polygons

    @environ.client_only
    def draw_colliders(self):
        for collider in self.colliders:
            points = self.entity.transform.transform_points_to_pyarcade_space(collider)
            points = [(point.x, point.y) for point in points]
            environ.arcade.draw_polygon_filled(points, COLLIDER_DRAW_COLOR)


class ManualCollider(Collider):
    def __init__(self, collision_data: list, solid: bool = True):
        super().__init__()
        self._colliders: list = collision_data
        self.colliders: list = collision_data
        self.solid: bool = solid

    def init_unserialized(self, deserializer):
        super().init_unserialized(deserializer)
        self.colliders = self._colliders

    def duplicate(self, new_entity):
        new_component = self.__class__(self.colliders, self.solid)
        return new_component


class SingleCollider(Collider):
    def __init__(self, tmx_data=None, tileset_name: str =None, relative_gid: int =None, solid: bool =None):
        """Must provide either tmx_data or (tileset_name and relative_gid and solid)."""
        super().__init__()
        if tmx_data is not None:
            self.tileset_name, self.relative_gid = environ.game.gid_to_tile_reference(tmx_data.gid)
            self.solid: bool = tmx_data.properties.get('solid', True)
        if tileset_name is not None:
            self.tileset_name = tileset_name
        if relative_gid is not None:
            self.relative_gid = relative_gid
        if solid is not None:
            self.solid = solid

        self.colliders: list = make_colliders_from_tile(environ.game.get_tile_by_tile_reference(self.tileset_name, self.relative_gid))

    def init_unserialized(self, deserializer):
        self.colliders = make_colliders_from_tile(deserializer.context.get_tile_by_tile_reference(self.tileset_name, self.relative_gid))
        super().init_unserialized(deserializer)

    def duplicate(self, new_entity):
        new_component = self.__class__(tileset_name=self.tileset_name, relative_gid=self.relative_gid, solid=self.solid)
        return new_component


class MultiCollider(Collider):
    collider_map = serialize.Unserialized()

    def __init__(self):
        super().__init__()
        self.collider_map: Optional[dict] = None

    def duplicate(self, new_entity):
        # Collider_map is set up when the component is attached to its entity
        new_component = self.__class__()
        return new_component

    def on_framesets_changed(self, framesets: dict, game):
        self.collider_map = {}
        for name, frameset in framesets.items():
            t: pytiled_parser.Tile = game.find_frameset(
                frameset.frameset)

            if t is None:
                raise RuntimeError(f"Frameset {frameset.frameset} does not exist in Tiled map.")

            flipped_horizontally = utils.is_flipped_horizontally(self.entity.gid)
            flipped_vertically = utils.is_flipped_vertically(self.entity.gid)
            t.flipped_horizontally = flipped_horizontally != frameset.flipped_horizontally
            t.flipped_vertically = flipped_vertically != frameset.flipped_vertically

            addcol = make_colliders_from_tile(t)
            self.collider_map[name] = addcol

            t.flipped_horizontally = False
            t.flipped_vertically = False

    def on_frameset_changed(self, new_frameset: dict):
        self.colliders = self.collider_map.get(new_frameset, "")

        # Force a recalculation next time collision might occur
        self._transformed_colliders = None
        self._transformed_collider_polygons = None

    def init_unserialized(self, deserializer):
        self.colliders = None
        super().init_unserialized(deserializer)


def make_colliders_from_tile(tile) -> list[Optional[list[Vector2]]]:
    ret: list[Optional[list[Vector2]]] = []
    if tile.objects is None:
        return ret
    for hitbox in tile.objects.tiled_objects:
        ret.append(make_collider_from_hitbox(hitbox))
    return ret


def make_collider_from_hitbox(hitbox) -> Optional[list[Vector2]]:
    points = []
    if isinstance(hitbox, pytiled_parser.tiled_object.Rectangle):
        if hitbox.size is None:
            sys.stderr.write(
                "Warning: Rectangle hitbox created for without a "
                "height or width Ignoring.\n"
            )
            return None

        points.append(Vector2f(hitbox.coordinates.x, hitbox.coordinates.y))
        points.append(Vector2f(hitbox.coordinates.x + hitbox.size.width, hitbox.coordinates.y))
        points.append(Vector2f(hitbox.coordinates.x + hitbox.size.width, hitbox.coordinates.y + hitbox.size.height))
        points.append(Vector2f(hitbox.coordinates.x, hitbox.coordinates.y + hitbox.size.height))

    elif isinstance(
        hitbox, pytiled_parser.tiled_object.Polygon
    ) or isinstance(hitbox, pytiled_parser.tiled_object.Polyline):
        for coord in hitbox.points:
            points.append(Vector2f(coord.x + hitbox.coordinates.x, coord.y + hitbox.coordinates.y))

        if points[0][0] == points[-1][0] and points[0][1] == points[-1][1]:
            points.pop()

        clockwise_counter = 0.0
        for i in range(0, len(points)):
            clockwise_counter += (points[i].x - points[i-1].x) * (points[i].y + points[i-1].y)
        if clockwise_counter > 0:
            points.reverse()

    elif isinstance(hitbox, pytiled_parser.tiled_object.Ellipse):
        if not hitbox.size:
            sys.stderr.write(
                f"Warning: Ellipse hitbox created without a height "
                f" or width. Ignoring.\n"
            )
            return None

        hw = hitbox.size.width / 2
        hh = hitbox.size.height / 2
        cx = hitbox.coordinates.x
        cy = hitbox.coordinates.y

        total_steps = 8
        angles = [
            step / total_steps * 2 * math.pi for step in range(total_steps)
        ]
        for angle in angles:
            x = hw * math.cos(angle) + cx
            y = -(hh * math.sin(angle) + cy)
            points.append(Vector2f(x, y))
    elif isinstance(hitbox, pytiled_parser.tiled_object.Point):
        return None
    else:
        sys.stderr.write(f"Warning: Hitbox type {type(hitbox)} not supported.\n")
        return None

    return points


def make_shapely_polygons(poly_a, poly_b) -> tuple:
    return Polygon(poly_a), Polygon(poly_b)


def are_polygons_intersecting(poly_a, poly_b) -> bool:
    r2 = False
    r1 = poly_a.intersects(poly_b)
    if r1:
        r2 = poly_a.touches(poly_b)
    return r1 and not r2


def minimum_translation_vector(poly_a, poly_b) -> Optional[Vector2]:
    """
    If the polygons do not intersect, return None.
    If the polygons do intersect, return the minimum translation
    vector for poly_a. (That is, the translation vector to apply to
    poly_a such that it no longer intersects with poly_b.
    """

    diff = minkowski_difference(poly_a, poly_b)
    minkowski_intersecting = is_point_in_polygon(0, 0, diff)

    if minkowski_intersecting:
        sdiff = Polygon(diff)
        npts = nearest_points(sdiff.exterior, Point(0, 0))
        return Vector2f(-npts[0].x, -npts[0].y)
    return None


def is_point_in_polygon(x: float, y: float, polygon_point_list: list) -> bool:

    shapely_point = Point(x, y)
    shapely_polygon = Polygon(polygon_point_list)

    return shapely_polygon.contains(shapely_point)


def _rotate_polygon_points(polygon) -> list:
    pos = 0
    for i in range(1, len(polygon)):
        if polygon[i].y < polygon[pos].y or polygon[i].y == polygon[pos].y and polygon[i].x < polygon[pos].x:
            pos = i

    # Rotate points:
    if pos != 0:
        return polygon[pos:] + polygon[:pos]
    return polygon[:]


def minkowski_sum(P: list, Q: list) -> list:
    # the first vertex must be the lowest
    P = _rotate_polygon_points(P)
    Q = _rotate_polygon_points(Q)

    # Ensure cyclic indexing
    P.append(P[0])
    P.append(P[1])
    Q.append(Q[0])
    Q.append(Q[1])

    # Run minkowski
    result = []
    i = 0
    j = 0
    while i < len(P) - 2 or j < len(Q) - 2:
        result.append(P[i] + Q[j])
        cross = np.cross(P[i + 1] - P[i], Q[j + 1] - Q[j])
        if cross >= 0: i += 1
        if cross <= 0: j += 1

    return result


def minkowski_difference(P: list, Q: list) -> list:
    return minkowski_sum(P, [q * -1 for q in Q])
