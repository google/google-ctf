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

from __future__ import annotations

from collections import deque
import logging
import math

import arcade
import numpy as np
import xxhash

BASIC_SHAPES = {
    3: "TRIANGLE",
    4: "RECTANGLE",
}


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.npa = np.array([self.x, self.y])


class Vector(Point):
    def __init__(self, x: int, y: int):
        super().__init__(x, y)
        self.unit = self.unit_vector()
        self.orthogonal = self.ortho()

    def unit_vector(self) -> float:
        return self.npa / np.linalg.norm(self.npa)

    def angle(self, other: Vector) -> float:
        return 180 - np.arccos(
            np.clip(np.dot(self.unit, other.unit), -1, 1)) * 180 / np.pi

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
        self.hck_hash = None

        self._update(outline)

    def _update(self, new_outline):
        self.outline = new_outline
        self.get_edges()
        self.get_vectors()
        self.get_angles()
        self.outline_array()

        if not self.is_convex():
            logging.error(
                f"Shape with points {[(i.x, i.y) for i in self.outline]} and angles {self.angles} is not a "
                f"polygon")

    def outline_array(self):
        self.outline_npa = np.array([(i.x, i.y) for i in self.outline])
        self.hashable_outline = {(i.x, i.y) for i in self.outline}
        self.hck_hash = self.dump_hashed()

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


def to_bytes(i):
    i = int(round(i)) & 0xffff
    return i.to_bytes(2, byteorder='big')


class Rectangle:
    def __init__(self, x1, x2, y1, y2):
        self._x1 = x1
        self._x2 = x2
        self._y1 = y1
        self._y2 = y2

    def x1(self):
        return self._x1

    def x2(self):
        return self._x2

    def y1(self):
        return self._y1

    def y2(self):
        return self._y2

    def collides(self, other: Rectangle):
        return (self.x1() <= other.x2() and self.x2() >= other.x1() and
                self.y1() <= other.y2() and self.y2() >= other.y1())

    def expand(self, amount):
        return Rectangle(self.x1() - amount, self.x2() + amount, self.y1() - amount,
                         self.y2() + amount)


class Hitbox(Polygon):
    def __init__(self, outline):
        super().__init__(outline)
        logging.debug(f"Created hitbox at {self.outline_npa}")

    def update(self, new_outline):
        self._update(new_outline)

    def _draw(self):
        r = self.get_rect()
        if r.x2() < r.x1() or r.y2() < r.y1():
            return
        arcade.draw_lrtb_rectangle_outline(r.x1(), r.x2(), r.y2(), r.y1(),
                                           arcade.color.RED)

    def collides(self, other: Hitbox):
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

    def centers_displacement(self, other: Hitbox):
        """
        Return the displacement between the geometric center of p1 and p2.
        """
        # geometric center
        c1 = np.mean(self.outline_npa, axis=0)
        c2 = np.mean(other.outline_npa, axis=0)
        return c2 - c1

    def is_separating_axis(self, o: np.array, outline: list[Point]):
        min1, max1 = float('+inf'), float('-inf')
        min2, max2 = float('+inf'), float('-inf')

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

    def get_highest_point(self):
        max_height = -math.inf
        for i in self.outline:
            max_height = max(max_height, i.y)
        return max_height

    def get_lowest_point(self):
        min_height = math.inf
        for i in self.outline:
            min_height = min(min_height, i.y)
        return min_height

    def get_rightmost_point(self):
        max_x = -math.inf
        for i in self.outline:
            max_x = max(max_x, i.x)
        return max_x

    def get_leftmost_point(self):
        min_x = math.inf
        for i in self.outline:
            min_x = min(min_x, i.x)
        return min_x

    def get_height(self):
        return round(self.get_highest_point() - self.get_lowest_point(),2)

    def get_width(self):
        return self.get_rightmost_point() - self.get_leftmost_point()

    def get_rect(self):
        return Rectangle(self.get_leftmost_point(), self.get_rightmost_point(),
                         self.get_lowest_point(), self.get_highest_point())


class HitboxCollection:
    def __init__(self, hitboxes: list[Hitbox] = None):
        self.hitboxes = hitboxes
        self.polys = []
        self.original_length = len(hitboxes)

    # bold assumption: when we read the tiles in horizontal order it should
    # already be adjacent
    def combine_y(self):
        d = deque(self.hitboxes)
        tmp = [d.popleft()]
        current_y = tmp[0].get_highest_point()

        while d:
            tmp_el = d.popleft()
            if tmp[-1].get_common_edge(tmp_el):
                if tmp_el.get_highest_point() == current_y:
                    tmp.append(tmp_el)
                else:
                    self.polys.append(tmp)
                    tmp = [tmp_el]
                    current_y = tmp_el.get_highest_point()
            else:
                self.polys.append(tmp)
                tmp = [tmp_el]
                current_y = tmp_el.get_highest_point()

        self.polys.append(tmp)

        res = []
        for i in self.polys:
            if len(i) == 1:
                res.append(i[0])
            else:
                res.append(self.combine_poly(i))
        self.polys = res

    def combine_x(self):
        a = sorted(self.polys, key=lambda x: (x.get_leftmost_point(),
                                              x.get_highest_point()))
        d = deque(a)
        tmp = [d.popleft()]
        current_x = tmp[0].get_leftmost_point()
        current_width = tmp[0].get_width()

        res = []

        while d:
            tmp_el = d.popleft()
            if tmp[-1].get_common_edge(tmp_el):
                if tmp_el.get_leftmost_point() == current_x:
                    if tmp_el.get_width() == current_width:
                        tmp.append(tmp_el)
                    else:
                        res.append(tmp)
                        tmp = [tmp_el]
                        current_x = tmp_el.get_leftmost_point()
                        current_width = tmp_el.get_width()
                else:
                    res.append(tmp)
                    tmp = [tmp_el]
                    current_x = tmp_el.get_leftmost_point()
                    current_width = tmp_el.get_width()
            else:
                res.append(tmp)
                tmp = [tmp_el]
                current_x = tmp_el.get_leftmost_point()
                current_width = tmp_el.get_width()

        res.append(tmp)

        res2 = []
        for i in res:
            if len(i) == 1:
                res2.append(i[0])
            else:
                res2.append(self.combine_poly(i))

        self.polys = res2

    def dump_polys(self):

        logging.debug(f"Reduced polygon size from {self.original_length} --> "
                      f"{len(self.polys)}")
        return self.polys

    @staticmethod
    def combine_poly(poly: list[Hitbox]):
        max_y = max(i.get_highest_point() for i in poly)
        max_x = max(i.get_rightmost_point() for i in poly)
        min_y = min(i.get_lowest_point() for i in poly)
        min_x = min(i.get_leftmost_point() for i in poly)

        return Hitbox(
            [Point(min_x, max_y),
             Point(max_x, max_y),
             Point(max_x, min_y),
             Point(min_x, min_y)]
        )


def main():
    p1 = Hitbox([Point(1, 0), Point(0, 1), Point(0, 0)])
    p2 = Hitbox([Point(1, 0), Point(1, 1), Point(0, 0)])
    p3 = Hitbox([Point(3, 0), Point(2, 1), Point(2, 0)])

    r1 = Hitbox([
        Point(0, 0),
        Point(0, 3),
        Point(3, 3),
        Point(3, 0),
    ])
    r2 = Hitbox([
        Point(2, 2),
        Point(2, 5),
        Point(5, 5),
        Point(5, 2),
    ])

    r3 = Hitbox([
        Point(1, 2),
        Point(1, 5),
        Point(2, 5),
        Point(2, 2),
    ])

    r4 = Hitbox([
        Point(2, 1),
        Point(2, 2),
        Point(5, 2),
        Point(5, 1),
    ])

    r5 = Hitbox([
        Point(-2, 1),
        Point(-2, 2),
        Point(1, 2),
        Point(1, 1),
    ])

    p4 = Hitbox([Point(56.3333, 72.3333), Point(66.33330000000001, 72.3333),
                 Point(66.33330000000001, 82.3333), Point(56.3333, 82.3333)])

    p5 = Hitbox([Point(96.0, 96.0), Point(304.0, 96.0),
                 Point(304.0, 302.66700000000003), Point(96.0, 302.66700000000003)])

    print(p1.collides(p2))
    print(p1.collides(p3))
    print(p1.collides(p4))
    print(p1.collides(p5))
    print(p1.angles)

    print(p4.collides(p5))
    print(p5.collides(p4))

    print(r1.collides(r2))
    print(r1.collides(r3))

    print(r1.collides(r4))
    print(r1.collides(r5))

    s = '''Hitbox([Point(16, 288), Point(32, 288), Point(32, 272), Point(16, 272)])
            Hitbox([Point(32, 288), Point(48, 288), Point(48, 272), Point(32, 272)])
            Hitbox([Point(48, 288), Point(64, 288), Point(64, 272), Point(48, 272)])
            Hitbox([Point(64, 288), Point(80, 288), Point(80, 272), Point(64, 272)])
            Hitbox([Point(80, 288), Point(96, 288), Point(96, 272), Point(80, 272)])
            Hitbox([Point(96, 288), Point(112, 288), Point(112, 272), Point(96, 272)])
            Hitbox([Point(112, 288), Point(128, 288), Point(128, 272), Point(112, 272)])
            Hitbox([Point(128, 288), Point(144, 288), Point(144, 272), Point(128, 272)])
            Hitbox([Point(144, 288), Point(160, 288), Point(160, 272), Point(144, 272)])
            Hitbox([Point(160, 288), Point(176, 288), Point(176, 272), Point(160, 272)])
            Hitbox([Point(176, 288), Point(192, 288), Point(192, 272), Point(176, 272)])
            Hitbox([Point(192, 288), Point(208, 288), Point(208, 272), Point(192, 272)])
            Hitbox([Point(208, 288), Point(224, 288), Point(224, 272), Point(208, 272)])
            Hitbox([Point(224, 288), Point(240, 288), Point(240, 272), Point(224, 272)])
            Hitbox([Point(240, 288), Point(256, 288), Point(256, 272), Point(240, 272)])
            Hitbox([Point(256, 288), Point(272, 288), Point(272, 272), Point(256, 272)])
            Hitbox([Point(272, 288), Point(288, 288), Point(288, 272), Point(272, 272)])
            Hitbox([Point(288, 288), Point(304, 288), Point(304, 272), Point(288, 272)])
            Hitbox([Point(16, 272), Point(32, 272), Point(32, 256), Point(16, 256)])
            Hitbox([Point(288, 272), Point(304, 272), Point(304, 256), Point(288, 256)])
            Hitbox([Point(16, 256), Point(32, 256), Point(32, 240), Point(16, 240)])
            Hitbox([Point(288, 256), Point(304, 256), Point(304, 240), Point(288, 240)])
            Hitbox([Point(16, 240), Point(32, 240), Point(32, 224), Point(16, 224)])
            Hitbox([Point(288, 240), Point(304, 240), Point(304, 224), Point(288, 224)])
            Hitbox([Point(16, 224), Point(32, 224), Point(32, 208), Point(16, 208)])
            Hitbox([Point(288, 224), Point(304, 224), Point(304, 208), Point(288, 208)])
            Hitbox([Point(16, 208), Point(32, 208), Point(32, 192), Point(16, 192)])
            Hitbox([Point(288, 208), Point(304, 208), Point(304, 192), Point(288, 192)])
            Hitbox([Point(16, 192), Point(32, 192), Point(32, 176), Point(16, 176)])
            Hitbox([Point(288, 192), Point(304, 192), Point(304, 176), Point(288, 176)])
            Hitbox([Point(16, 176), Point(32, 176), Point(32, 160), Point(16, 160)])
            Hitbox([Point(288, 176), Point(304, 176), Point(304, 160), Point(288, 160)])
            Hitbox([Point(16, 160), Point(32, 160), Point(32, 144), Point(16, 144)])
            Hitbox([Point(288, 160), Point(304, 160), Point(304, 144), Point(288, 144)])
            Hitbox([Point(16, 144), Point(32, 144), Point(32, 128), Point(16, 128)])
            Hitbox([Point(288, 144), Point(304, 144), Point(304, 128), Point(288, 128)])
            Hitbox([Point(16, 128), Point(32, 128), Point(32, 112), Point(16, 112)])
            Hitbox([Point(288, 128), Point(304, 128), Point(304, 112), Point(288, 112)])
            Hitbox([Point(16, 112), Point(32, 112), Point(32, 96), Point(16, 96)])
            Hitbox([Point(288, 112), Point(304, 112), Point(304, 96), Point(288, 96)])
            Hitbox([Point(16, 96), Point(32, 96), Point(32, 80), Point(16, 80)])
            Hitbox([Point(288, 96), Point(304, 96), Point(304, 80), Point(288, 80)])
            Hitbox([Point(16, 80), Point(32, 80), Point(32, 64), Point(16, 64)])
            Hitbox([Point(288, 80), Point(304, 80), Point(304, 64), Point(288, 64)])
            Hitbox([Point(16, 64), Point(32, 64), Point(32, 48), Point(16, 48)])
            Hitbox([Point(32, 64), Point(48, 64), Point(48, 48), Point(32, 48)])
            Hitbox([Point(48, 64), Point(64, 64), Point(64, 48), Point(48, 48)])
            Hitbox([Point(64, 64), Point(80, 64), Point(80, 48), Point(64, 48)])
            Hitbox([Point(80, 64), Point(96, 64), Point(96, 48), Point(80, 48)])
            Hitbox([Point(96, 64), Point(112, 64), Point(112, 48), Point(96, 48)])
            Hitbox([Point(112, 64), Point(128, 64), Point(128, 48), Point(112, 48)])
            Hitbox([Point(128, 64), Point(144, 64), Point(144, 48), Point(128, 48)])
            Hitbox([Point(144, 64), Point(160, 64), Point(160, 48), Point(144, 48)])
            Hitbox([Point(160, 64), Point(176, 64), Point(176, 48), Point(160, 48)])
            Hitbox([Point(176, 64), Point(192, 64), Point(192, 48), Point(176, 48)])
            Hitbox([Point(192, 64), Point(208, 64), Point(208, 48), Point(192, 48)])
            Hitbox([Point(208, 64), Point(224, 64), Point(224, 48), Point(208, 48)])
            Hitbox([Point(224, 64), Point(240, 64), Point(240, 48), Point(224, 48)])
            Hitbox([Point(240, 64), Point(256, 64), Point(256, 48), Point(240, 48)])
            Hitbox([Point(256, 64), Point(272, 64), Point(272, 48), Point(256, 48)])
            Hitbox([Point(272, 64), Point(288, 64), Point(288, 48), Point(272, 48)])
            Hitbox([Point(288, 64), Point(304, 64), Point(304, 48), Point(288, 48)])'''.split(
        '\n')

    s = [eval(i) for i in s]

    print(s[0].get_common_edge(s[1]))
    print(s[1].get_common_edge(s[2]))
    print(s[2].get_common_edge(s[3]))
    print(s[0].get_common_edge(s[-1]))

    h = HitboxCollection(s)
    h.combine_y()
    print(h.polys)
    h.combine_x()
    print(h.polys)

    rt1 = Hitbox([
        Point(0, 0),
        Point(0, 1),
        Point(1, 1),
        Point(1, 0),
    ])
    rt2 = Hitbox([
        Point(0, 1),
        Point(0, 2),
        Point(1, 2),
        Point(1, 1),
    ])

    print("============== Test 2 ==================")
    h = HitboxCollection([rt1, rt2])
    print(h.hitboxes)
    h.combine_y()
    print(h.polys)
    h.combine_x()
    print(h.polys)

    print(rt1.get_common_edge(rt2))

    print(h.dump_polys())


if __name__ == '__main__':
    main()
