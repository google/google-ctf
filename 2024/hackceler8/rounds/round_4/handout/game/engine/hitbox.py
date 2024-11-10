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
from collections import deque
from game.engine.point import Point
from game.engine import gfx
import logging
import xxhash


class Rectangle:
    def __init__(self, x1, x2, y1, y2):
        self.x1 = round(x1, 2)
        self.x2 = round(x2, 2)
        self.y1 = round(y1, 2)
        self.y2 = round(y2, 2)

    def collides(self, other: Rectangle):
        return (
                self.x1 <= other.x2
                and self.x2 >= other.x1
                and self.y1 <= other.y2
                and self.y2 >= other.y1
        )

    # Get the minimum push vector required to push other out.
    def get_mpv(self, other: Rectangle):
        pvs = [
            Point(self.x2 - other.x1, 0),
            Point(self.x1 - other.x2, 0),
            Point(0, self.y2 - other.y1),
            Point(0, self.y1 - other.y2),
        ]
        mpv = pvs[0]
        md = abs(mpv.x) + abs(mpv.y)
        for pv in pvs:
            d = abs(pv.x) + abs(pv.y)
            if md > d:
                md = d
                mpv = pv
        return mpv

    def has_common_edge(self, other: Rectangle):
        # Other is right above or below
        if self.x1 == other.x1 and self.x2 == other.x2:
            return self.y1 == other.y2 or self.y2 == other.y1
        # Other is to the left or right
        if self.y1 == other.y1 and self.y2 == other.y2:
            return self.x1 == other.x2 or self.x2 == other.x1
        return False

    def expand(self, amount):
        return Rectangle(
            self.x1 - amount,
            self.x2 + amount,
            self.y1 - amount,
            self.y2 + amount,
        )

    def offset(self, dx, dy):
        return Rectangle(
            self.x1 + dx,
            self.x2 + dx,
            self.y1 + dy,
            self.y2 + dy,
        )

    def __repr__(self):
        return "[x:%.2f-%.2f, y:%.2f-%.2f]" % (self.x1, self.x2, self.y1, self.y2)


class Hitbox(Rectangle):
    def __init__(self, x1, x2, y1, y2):
        super().__init__(x1, x2, y1, y2)
        self.rect_hash = self.get_rect_hash()

    def update(self, rect):
        self.x1 = round(rect.x1, 2)
        self.x2 = round(rect.x2, 2)
        self.y1 = round(rect.y1, 2)
        self.y2 = round(rect.y2, 2)
        self.rect_hash = self.get_rect_hash()

    def get_rect_hash(self):
        return xxhash.xxh64(str((self.x1, self.x2, self.y1, self.y2))).hexdigest()

    def get_highest_point(self):
        return self.y2

    def get_lowest_point(self):
        return self.y1

    def get_rightmost_point(self):
        return self.x2

    def get_leftmost_point(self):
        return self.x1

    def get_height(self):
        return self.get_highest_point() - self.get_lowest_point()

    def get_width(self):
        return self.get_rightmost_point() - self.get_leftmost_point()


class HitboxCollection:
    def __init__(self, hitboxes: list[Hitbox] = None):
        self.hitboxes = hitboxes
        self.rects = []
        self.original_length = len(hitboxes)

    # bold assumption: when we read the tiles in horizontal order it should
    # already be adjacent
    def combine_y(self):
        d = deque(self.hitboxes)
        tmp = [d.popleft()]
        current_y = tmp[0].get_highest_point()

        while d:
            tmp_el = d.popleft()
            if tmp[-1].has_common_edge(tmp_el):
                if tmp_el.get_highest_point() == current_y:
                    tmp.append(tmp_el)
                else:
                    self.rects.append(tmp)
                    tmp = [tmp_el]
                    current_y = tmp_el.get_highest_point()
            else:
                self.rects.append(tmp)
                tmp = [tmp_el]
                current_y = tmp_el.get_highest_point()

        self.rects.append(tmp)

        res = []
        for i in self.rects:
            if len(i) == 1:
                res.append(i[0])
            else:
                res.append(self.combine_rect(i))
        self.rects = res

    def combine_x(self):
        a = sorted(
            self.rects,
            key=lambda x: (x.get_leftmost_point(), x.get_highest_point()),
        )
        d = deque(a)
        tmp = [d.popleft()]
        current_x = tmp[0].get_leftmost_point()
        current_width = tmp[0].get_width()

        res = []

        while d:
            tmp_el = d.popleft()
            if tmp[-1].has_common_edge(tmp_el):
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
                res2.append(self.combine_rect(i))

        self.rects = res2

    def dump_rects(self):

        logging.debug(
            f"Reduced rectangle size from {self.original_length} --> "
            f"{len(self.rects)}"
        )
        return self.rects

    @staticmethod
    def combine_rect(rect: list[Hitbox]):
        max_y = max(i.get_highest_point() for i in rect)
        max_x = max(i.get_rightmost_point() for i in rect)
        min_y = min(i.get_lowest_point() for i in rect)
        min_x = min(i.get_leftmost_point() for i in rect)

        return Hitbox(min_x, max_x, min_y, max_y)


def main():
    r1 = Hitbox(0, 3, 0, 3)
    r2 = Hitbox(2, 5, 2, 5)
    r3 = Hitbox(1, 2, 2, 5)
    r4 = Hitbox(2, 5, 1, 2)
    r5 = Hitbox(-2, 1, 1, 2)
    print(r1.collides(r2))
    print(r1.collides(r3))
    print(r1.collides(r4))
    print(r1.collides(r5))

    s = [
        Hitbox(16, 32, 272, 288), Hitbox(32, 48, 272, 288), Hitbox(48, 64, 272, 288),
        Hitbox(64, 80, 272, 288), Hitbox(80, 96, 272, 288), Hitbox(96, 112, 272, 288),
        Hitbox(112, 128, 272, 288), Hitbox(128, 144, 272, 288), Hitbox(144, 160, 272, 288),
        Hitbox(160, 176, 272, 288), Hitbox(176, 192, 272, 288), Hitbox(192, 208, 272, 288),
        Hitbox(208, 224, 272, 288), Hitbox(224, 240, 272, 288), Hitbox(240, 256, 272, 288),
        Hitbox(256, 272, 272, 288), Hitbox(272, 288, 272, 288), Hitbox(288, 304, 272, 288),
        Hitbox(16, 32, 256, 272), Hitbox(288, 304, 256, 272), Hitbox(16, 32, 240, 256),
        Hitbox(288, 304, 240, 256), Hitbox(16, 32, 224, 240), Hitbox(288, 304, 224, 240),
        Hitbox(16, 32, 208, 224), Hitbox(288, 304, 208, 224), Hitbox(16, 32, 192, 208),
        Hitbox(288, 304, 192, 208), Hitbox(16, 32, 176, 192), Hitbox(288, 304, 176, 192),
        Hitbox(16, 32, 160, 176), Hitbox(288, 304, 160, 176), Hitbox(16, 32, 144, 160),
        Hitbox(288, 304, 144, 160), Hitbox(16, 32, 128, 144), Hitbox(288, 304, 128, 144),
        Hitbox(16, 32, 112, 128), Hitbox(288, 304, 112, 128), Hitbox(16, 32, 96, 112),
        Hitbox(288, 304, 96, 112), Hitbox(16, 32, 80, 96), Hitbox(288, 304, 80, 96),
        Hitbox(16, 32, 64, 80), Hitbox(288, 304, 64, 80), Hitbox(16, 32, 48, 64),
        Hitbox(32, 48, 48, 64), Hitbox(48, 64, 48, 64), Hitbox(64, 80, 48, 64),
        Hitbox(80, 96, 48, 64), Hitbox(96, 112, 48, 64), Hitbox(112, 128, 48, 64),
        Hitbox(128, 144, 48, 64), Hitbox(144, 160, 48, 64), Hitbox(160, 176, 48, 64),
        Hitbox(176, 192, 48, 64), Hitbox(192, 208, 48, 64), Hitbox(208, 224, 48, 64),
        Hitbox(224, 240, 48, 64), Hitbox(240, 256, 48, 64), Hitbox(256, 272, 48, 64),
        Hitbox(272, 288, 48, 64), Hitbox(288, 304, 48, 64)
    ]

    print(s[0].has_common_edge(s[1]))
    print(s[1].has_common_edge(s[2]))
    print(s[2].has_common_edge(s[3]))
    print(s[0].has_common_edge(s[-1]))

    h = HitboxCollection(s)
    h.combine_y()
    print(h.rects)
    h.combine_x()
    print(h.rects)

    print("============== Test 2 ==================")
    rt1 = Hitbox(0, 1, 0, 1)
    rt2 = Hitbox(0, 1, 1, 2)
    h = HitboxCollection([rt1, rt2])
    print(h.hitboxes)
    h.combine_y()
    print(h.rects)
    h.combine_x()
    print(h.rects)

    print(rt1.has_common_edge(rt2))

    print(h.dump_rects())


if __name__ == "__main__":
    main()
