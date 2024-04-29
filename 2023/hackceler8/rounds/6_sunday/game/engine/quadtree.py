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
import uuid

class Node:
    def __init__(self, bounds, capacity):
        self.bounds = bounds
        self.capacity = capacity
        self.objects = []
        self.divided = False
        self.children = []

    def remove_by_id(self, idi):
        for obj in self.objects:
            if obj.idi == idi:
                self.objects.remove(obj)
                return True

        if self.divided:
            for child in self.children:
                if child.remove_by_id(idi):
                    return True
        return False

    def insert(self, obj):
        if not self.bounds.contains(obj):
            return False

        if len(self.objects) < self.capacity:
            self.objects.append(obj)
            return True

        if not self.divided:
            self.subdivide()

        if any(child.insert(obj) for child in self.children):
            return True

        return False

    def subdivide(self):
        x, y, w, h = self.bounds.x, self.bounds.y, self.bounds.w, self.bounds.h
        nw = Node(Bounds(x, y, w / 2, h / 2, str(uuid.uuid4())), self.capacity)
        ne = Node(Bounds(x + w / 2, y, w / 2, h / 2, str(uuid.uuid4())), self.capacity)

        sw = Node(Bounds(x, y - h / 2, w / 2, h / 2, str(uuid.uuid4())), self.capacity)
        se = Node(Bounds(x + w / 2, y - h / 2, w / 2, h / 2, str(uuid.uuid4())),
                  self.capacity)

        self.children = [nw, ne, sw, se]
        self.divided = True

        for obj in self.objects:
            for child in self.children:
                child.insert(obj)
        self.objects = []

    def query(self, region, found):
        logging.debug(f"Querying section {self.bounds.dump()}")
        if not self.bounds.intersects(region):
            return

        for obj in self.objects:
            if region.contains(obj):
                found.append(obj)

        if self.divided:
            for child in self.children:
                child.query(region, found)


class Bounds:
    def __init__(self, x, y, w, h, idi=None):
        self.x = x
        self.y = y
        self.w = w
        self.h = h
        self.idi = idi
        self.rect = [self.x, self.y, self.x + self.w, self.y - self.h]

    def dump(self):
        return f"{self.x, self.y, self.w, self.h, self.idi}"

    def contains(self, obj):
        res = (
                # check if in between x extremes
                obj.x >= self.x and
                obj.x < self.x + self.w and
                obj.y <= self.y  and
                obj.y >= self.y - self.h
        )
        logging.debug(res)
        return res

    def intersects(self, other):
        return intersect(self.rect, other.rect)

def intersect(rect1, rect2):
    x0_1, y0_1, x1_1, y1_1 = rect1
    x0_2, y0_2, x1_2, y1_2 = rect2

    # Check if one rectangle is to the right of the other
    if x0_1 > x1_2 or x0_2 > x1_1:
        return False

    # Check if one rectangle is above the other
    if y0_1 < y1_2 or y0_2 < y1_1:
        return False

    # If neither of the above conditions are true, the rectangles must intersect
    return True


class Quadtree:
    def __init__(self, bounds, capacity):
        self.root = Node(bounds, capacity)

    def insert(self, obj):
        return self.root.insert(obj)

    def query(self, region):
        found = []
        self.root.query(region, found)
        return found

    def remove_by_id(self, obj_id):
        return self.root.remove_by_id(obj_id)

    def update_by_id(self, obj_id, new_bound):
        self.remove_by_id(obj_id)
        self.insert(new_bound)


def main():
    # Define some sample objects (like game characters or obstacles) as bounds
    wall1 = Bounds(480, 2704, 16, 16, '1a89ad73-04a7-4f89-9b72-5589bccfb942')
    wall2 = Bounds(720, 2896, 16, 16, '890c2f8c-ba22-466e-ac26-b1de62387db0')
    player = Bounds(525.0, 2501.0, 10.0, 10.0, '5bc52efc-e808-40c2-a932-afe6e311f457')

    # Create a quadtree that covers the entire game space (e.g., 50x50)
    quadtree = Quadtree(Bounds(0, 0, 4800, 6400), capacity=4)

    # Insert objects into the quadtree
    quadtree.insert(wall1)
    quadtree.insert(wall2)
    quadtree.insert(player)

    # Query a region to find potential collisions
    region_of_interest = Bounds(757-32, 2794+32, 80, 80)
    potential_collisions = quadtree.query(region_of_interest)

    # Print the potential collisions
    print("Potential collisions:")
    for obj in potential_collisions:
        print(obj.idi)

if __name__ == '__main__':
    main()
