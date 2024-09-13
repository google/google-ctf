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

from __future__ import annotations
import logging
import numpy as np
import xxhash
from game.engine.point import Point


class Vector(Point):
    def __init__(self, x: int, y: int):
        super().__init__(x, y)
        self.unit = self.unit_vector()
        self.orthogonal = self.ortho()

    def unit_vector(self) -> float:
        return self.npa / np.linalg.norm(self.npa)

    def angle(self, other: Vector) -> float:
        return (
                180
                - np.arccos(np.clip(np.dot(self.unit, other.unit), -1, 1)) * 180 / np.pi
        )

    def ortho(self):
        return np.array([-self.y, self.x])


class Polygon:
    def __init__(self, outline: list[Point]):
        self.outline = outline
        self.edges = []
        self.vectors = []
        self.angles = []
        self.outline_npa = None
        self.hashable_outline = None
        self.outline_hash = None

        self.update_hitbox(outline)

    def _update(self, new_outline):
        self.outline = new_outline
        self.get_edges()
        self.get_vectors()
        self.get_angles()
        self.outline_array()

        if not self.is_convex():
            logging.error(
                f"Shape with points {[(i.x, i.y) for i in self.outline]} and angles"
                f" {self.angles} is not a polygon"
            )

    def outline_array(self):
        self.outline_npa = np.array([(i.x, i.y) for i in self.outline])
        self.hashable_outline = {(i.x, i.y) for i in self.outline}
        self.outline_hash = self.dump_hashed()

    def get_common_edge(self, o2):
        tmp = self.hashable_outline.intersection(o2.hashable_outline)
        return tmp

    def dump_hashed(self):
        return xxhash.xxh64(str(self.hashable_outline)).hexdigest()

    def get_edges(self) -> None:
        self.edges.clear()
        outline_all = [*self.outline, self.outline[0]]

        for i in range(0, len(outline_all) - 1):
            self.edges.append((outline_all[i], outline_all[i + 1]))

    def get_vectors(self) -> None:
        self.vectors.clear()
        for e in self.edges:
            self.vectors.append(Vector(e[1].x - e[0].x, e[1].y - e[0].y))

    def get_angles(self) -> None:
        self.angles.clear()
        vectors_all = [*self.vectors, self.vectors[0]]
        for i in range(len(vectors_all) - 1):
            self.angles.append(vectors_all[i].angle(vectors_all[i + 1]))

    def is_convex(self) -> bool:
        if len(self.edges) < 4:
            return True
        return all(i < 180 for i in self.angles)

    def dump_debug(self):
        return [(i.x, i.y) for i in self.outline]

    def collides(self, other: Polygon):
        edges = self.edges.copy()
        edges += other.edges

        orths = [i.orthogonal for i in self.vectors]
        orths += [i.orthogonal for i in other.vectors]

        push_vectors = []
        for o in orths:
            separates, pv = self.is_separating_axis(o, other.outline)

            if separates:
                # they do not collide and there is no push vector
                return False, None

            push_vectors.append(pv)

        mpv = min(push_vectors, key=(lambda v: np.dot(v, v)))

        # assert mpv pushes p1 away from p2
        d = self.centers_displacement(other)  # direction from p1 to p2
        logging.debug(d)
        if np.dot(d, mpv) > 0:  # if it's the same direction, then invert
            mpv = -mpv
        return True, mpv

    def centers_displacement(self, other: Polygon):
        """Return the displacement between the geometric center of p1 and p2."""
        # geometric center
        c1 = np.mean(self.outline_npa, axis=0)
        c2 = np.mean(other.outline_npa, axis=0)
        return c2 - c1

    def is_separating_axis(self, o: np.array, outline: list[Point]):
        min1, max1 = float("+inf"), float("-inf")
        min2, max2 = float("+inf"), float("-inf")

        for p in self.outline:
            proj = np.dot(p.npa, o)
            min1 = min(min1, proj)
            max1 = max(max1, proj)

        for p in outline:
            proj = np.dot(p.npa, o)
            min2 = min(min2, proj)
            max2 = max(max2, proj)

        if max1 >= min2 and max2 >= min1:
            d = min(max2 - min1, max1 - min2)
            # push a bit more than needed so the shapes do not overlap in future
            # tests due to float precision
            d_over_o_squared = d / np.dot(o, o) + 1e-10
            pv = d_over_o_squared * o
            return False, pv

        return True, None


def main():
    p1 = Polygon([Point(1, 0), Point(0, 1), Point(0, 0)])
    p2 = Polygon([Point(1, 0), Point(1, 1), Point(0, 0)])
    p3 = Polygon([Point(3, 0), Point(2, 1), Point(2, 0)])

    p4 = Polygon([
        Point(56.3333, 72.3333),
        Point(66.33330000000001, 72.3333),
        Point(66.33330000000001, 82.3333),
        Point(56.3333, 82.3333),
    ])

    p5 = Polygon([
        Point(96.0, 96.0),
        Point(304.0, 96.0),
        Point(304.0, 302.66700000000003),
        Point(96.0, 302.66700000000003),
    ])

    print(p1.collides(p2))
    print(p1.collides(p3))
    print(p1.collides(p4))
    print(p1.collides(p5))
    print(p1.angles)

    print(p4.collides(p5))
    print(p5.collides(p4))


if __name__ == "__main__":
    main()
