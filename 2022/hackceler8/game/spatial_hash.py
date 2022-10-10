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

from gametree import Vector2, Vector2i
import collections
from typing import List, Generator, Any
import functools

from shapely import speedups  # type: ignore
from shapely.geometry import Polygon, Point  # type: ignore
from shapely.ops import nearest_points

BUCKET_SIZE = 32

@functools.cache
def _point_to_bucket(point: Vector2) -> Vector2:
    return Vector2i(point.x, point.y) / BUCKET_SIZE

def _bresenham(x0: int, y0: int, x1: int, y1: int) -> Generator[tuple[int, int], Any, None]:
    """Yield integer coordinates on the line from (x0, y0) to (x1, y1).
    Input coordinates should be integers.
    The result will contain both the start and the end point.
    """
    dx = x1 - x0
    dy = y1 - y0

    xsign = 1 if dx > 0 else -1
    ysign = 1 if dy > 0 else -1

    dx = abs(dx)
    dy = abs(dy)

    if dx > dy:
        xx, xy, yx, yy = xsign, 0, 0, ysign
    else:
        dx, dy = dy, dx
        xx, xy, yx, yy = 0, ysign, xsign, 0

    D = 2*dy - dx
    y = 0


    x = 0
    while x < dx + BUCKET_SIZE:
        yield (x0 + x*xx + y*yx) // BUCKET_SIZE, (y0 + x*xy + y*yy) // BUCKET_SIZE
        if D >= 0:
            y += 1
            D -= 2*dx
        D += 2*dy
        x += BUCKET_SIZE

def _yield_edges(collider: List[Vector2]) -> Generator[tuple[Vector2, Vector2], Any, None]:
    for i in range(len(collider) - 1):
        yield (collider[i], collider[i + 1])
    yield (collider[-1], collider[0])


class SpatialHash:
    def __init__(self):
        self.buckets = collections.defaultdict(list)
        self.pbuckets = collections.defaultdict(list)
        self.solid = True

    def add(self, collider: List[Vector2]):
        pcollider = Polygon(collider)
        if len(collider) == 1:
            self.buckets[_point_to_bucket(collider[0])].append(collider)
            self.pbuckets[_point_to_bucket(collider[0])].append(collider)
            return
        for point1, point2 in _yield_edges(collider):
            for bucket in _bresenham(point1.x, point1.y, point2.x, point2.y):
                self.buckets[(bucket)].append(collider)
                self.pbuckets[(bucket)].append(pcollider)

    def get_colliders(self, collider: List[Vector2]) -> list[list[Vector2]]:
        if len(collider) == 1:
            bucket = _point_to_bucket(collider[0])
            return self.buckets[bucket]

        ret = {}
        for point1, point2 in _yield_edges(collider):
            for bucket in _bresenham(point1.x, point1.y, point2.x, point2.y):
                for collider in self.buckets[bucket]:
                    ret[id(collider)] = collider
        return list(ret.values())

    def get_pcolliders(self, collider: List[Vector2]) -> list[list[Vector2]]:
        if len(collider) == 1:
            bucket = _point_to_bucket(collider[0])
            return self.pbuckets[bucket]

        ret = {}
        for point1, point2 in _yield_edges(collider):
            for bucket in _bresenham(point1.x, point1.y, point2.x, point2.y):
                for collider in self.pbuckets[bucket]:
                    ret[id(collider)] = collider
        return list(ret.values())
