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

import math
from collections import deque
import colorsys

from PIL import Image
import arcade
import constants
from engine.coroutines import CoroutineSystem, sleep_ticks

BULLET_SIZE = 64
BASE_SHAPE_X = {'circle':0, 'rect':BULLET_SIZE, 'arrow':BULLET_SIZE*2}
# base shape, x scale, y scale, hitbox mult
# x,y scales assume angle=0 (rightwards)
SHAPES = {
    'circle': ('circle', 0.5, 0.5, 0.35),
    'rect': ('rect', 0.5, 0.5, 0.5),
    'arrow': ('arrow', 0.5, 0.5, 0.25),
    'oval': ('circle', 0.5, 0.25, 0.175),
}
RECT_MAZES = [([(0, 0), (0, 2), (0, 2), (0, 4), (0, 4), (0, 6), (1, 0), (1, 1), (1, 1),
   (1, 3), (1, 3), (1, 4), (1, 4), (1, 5), (1, 5), (1, 6), (2, 0), (2, 3),
   (2, 3), (2, 6), (3, 0), (3, 2), (3, 2), (3, 5), (3, 5), (3, 6), (4, 0),
   (4, 1), (4, 1), (4, 3), (4, 3), (4, 5), (4, 5), (4, 6), (5, 2), (5, 2),
   (5, 4), (5, 4), (6, 0), (6, 2), (6, 2), (6, 3), (6, 3), (6, 4), (6, 4),
   (6, 6), (7, 0), (7, 1), (7, 1), (7, 3), (7, 3), (7, 5), (7, 5), (7, 6),
   (8, 0), (8, 1), (8, 1), (8, 2), (8, 2), (8, 4), (8, 4), (8, 5), (8, 5),
   (8, 6), (9, 0), (9, 1), (9, 1), (9, 2), (9, 2), (9, 6), (10, 0), (10, 6)],
  [(0, 0), (1, 1), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (2, 1), (1, 1),
   (2, 2), (2, 4), (3, 0), (2, 1), (2, 2), (3, 3), (3, 4), (2, 4), (3, 0),
   (4, 1), (4, 2), (4, 3), (3, 3), (3, 4), (4, 1), (4, 2), (5, 3), (4, 3),
   (5, 4), (6, 1), (6, 2), (5, 3), (5, 4), (6, 5), (7, 0), (6, 1), (6, 2),
   (7, 4), (6, 5), (7, 0), (8, 2), (7, 4), (8, 2), (9, 3), (9, 4), (10, 2),
   (10, 3), (9, 3), (10, 4), (9, 4), (10, 5), (11, 0), (11, 1), (11, 2),
   (10, 2), (11, 3), (10, 3), (11, 4), (10, 4), (11, 5), (10, 5)]),
 ([(0, 0), (0, 3), (0, 3), (0, 6), (1, 0), (1, 2), (1, 2), (1, 6), (2, 0),
   (2, 1), (2, 1), (2, 4), (2, 4), (2, 6), (3, 0), (3, 2), (3, 2), (3, 3),
   (3, 3), (3, 5), (3, 5), (3, 6), (4, 0), (4, 1), (4, 1), (4, 2), (4, 2),
   (4, 5), (4, 5), (4, 6), (5, 1), (5, 1), (5, 3), (5, 3), (5, 4), (5, 4),
   (6, 0), (6, 3), (6, 3), (6, 4), (6, 4), (6, 6), (7, 0), (7, 2), (7, 2),
   (7, 3), (7, 3), (7, 6), (8, 0), (8, 1), (8, 1), (8, 2), (8, 2), (8, 5),
   (8, 5), (8, 6), (9, 0), (9, 2), (9, 2), (9, 4), (9, 4), (9, 5), (9, 5),
   (9, 6), (10, 0), (10, 1), (10, 1), (10, 3), (10, 3), (10, 6)],
  [(1, 0), (0, 0), (0, 1), (0, 2), (1, 3), (0, 3), (1, 4), (0, 4), (0, 5),
   (2, 0), (1, 0), (2, 1), (2, 2), (2, 3), (1, 3), (2, 4), (1, 4), (2, 0),
   (2, 1), (3, 2), (2, 2), (2, 3), (2, 4), (3, 5), (4, 1), (3, 2), (4, 3),
   (4, 4), (3, 5), (4, 1), (4, 3), (4, 4), (6, 1), (6, 2), (6, 4), (7, 0),
   (7, 1), (6, 1), (6, 2), (7, 4), (6, 4), (7, 5), (7, 0), (7, 1), (8, 3),
   (8, 4), (7, 4), (7, 5), (9, 1), (9, 2), (9, 3), (8, 3), (8, 4), (9, 1),
   (9, 2), (9, 3), (11, 0), (11, 1), (11, 2), (11, 3), (11, 4), (11, 5)]),
 ([(0, 0), (0, 2), (0, 2), (0, 6), (1, 0), (1, 1), (1, 1), (1, 3), (1, 3),
   (1, 5), (1, 5), (1, 6), (2, 0), (2, 6), (3, 0), (3, 1), (3, 1), (3, 6),
   (4, 0), (4, 1), (4, 1), (4, 4), (4, 4), (4, 6), (5, 3), (5, 3), (5, 4),
   (5, 4), (6, 0), (6, 1), (6, 1), (6, 2), (6, 2), (6, 3), (6, 3), (6, 4),
   (6, 4), (6, 5), (6, 5), (6, 6), (7, 0), (7, 1), (7, 1), (7, 3), (7, 3),
   (7, 6), (8, 0), (8, 3), (8, 3), (8, 6), (9, 0), (9, 3), (9, 3), (9, 6),
   (10, 0), (10, 6)],
  [(0, 0), (0, 1), (0, 2), (1, 3), (0, 3), (1, 4), (0, 4), (0, 5), (2, 1),
   (2, 2), (2, 3), (1, 3), (1, 4), (2, 5), (3, 0), (3, 1), (2, 1), (3, 2),
   (2, 2), (3, 3), (2, 3), (3, 4), (2, 5), (3, 0), (3, 1), (4, 2), (3, 2),
   (4, 3), (3, 3), (4, 4), (3, 4), (4, 5), (5, 1), (5, 2), (4, 2), (4, 3),
   (4, 4), (5, 5), (4, 5), (6, 1), (5, 1), (5, 2), (5, 5), (6, 1), (7, 4),
   (8, 1), (8, 2), (8, 3), (8, 4), (7, 4), (9, 0), (9, 1), (8, 1), (8, 2),
   (8, 3), (9, 4), (8, 4), (9, 5), (9, 0), (10, 1), (9, 1), (10, 2), (10, 3),
   (10, 4), (9, 4), (9, 5), (11, 0), (11, 1), (10, 1), (11, 2), (10, 2),
   (11, 3), (10, 3), (11, 4), (10, 4), (11, 5)]),
 ([(0, 0), (0, 2), (0, 2), (0, 6), (1, 0), (1, 1), (1, 1), (1, 2), (1, 2),
   (1, 4), (1, 4), (1, 6), (2, 0), (2, 1), (2, 1), (2, 3), (2, 3), (2, 4),
   (2, 4), (2, 5), (2, 5), (2, 6), (3, 0), (3, 1), (3, 1), (3, 4), (3, 4),
   (3, 5), (3, 5), (3, 6), (4, 0), (4, 2), (4, 2), (4, 5), (4, 5), (4, 6),
   (5, 2), (5, 2), (5, 4), (5, 4), (5, 5), (5, 5), (6, 0), (6, 4), (6, 4),
   (6, 5), (6, 5), (6, 6), (7, 0), (7, 5), (7, 5), (7, 6), (8, 0), (8, 3),
   (8, 3), (8, 6), (9, 0), (9, 2), (9, 2), (9, 6), (10, 0), (10, 6)],
  [(0, 0), (0, 1), (0, 2), (1, 3), (0, 3), (0, 4), (1, 5), (0, 5), (2, 2),
   (1, 3), (2, 4), (1, 5), (3, 2), (2, 2), (2, 4), (4, 1), (4, 2), (3, 2),
   (4, 3), (5, 0), (4, 1), (4, 2), (5, 3), (4, 3), (5, 0), (6, 1), (6, 2),
   (5, 3), (7, 0), (7, 1), (6, 1), (7, 2), (6, 2), (7, 3), (7, 4), (7, 0),
   (8, 1), (7, 1), (8, 2), (7, 2), (8, 3), (7, 3), (7, 4), (9, 1), (8, 1),
   (8, 2), (9, 3), (8, 3), (9, 4), (9, 5), (10, 0), (10, 1), (9, 1), (10, 2),
   (10, 3), (9, 3), (10, 4), (9, 4), (9, 5), (11, 0), (10, 0), (11, 1), (10, 1),
   (11, 2), (10, 2), (11, 3), (10, 3), (11, 4), (10, 4), (11, 5)])]

CIRC_MAZES = [
    ('''
    0011111111111100
    1110111001110101
    0010000010001110
    1111111111111011
    '''.strip().split(),
    '''
    0010000010000010
    0100101110011001
    1010010100101000
    '''.strip().split()),
    ('''
    0011111111111100
    1011011111110111
    0110000000101100
    1111111101111111
    '''.strip().split(),
    '''
    0010000000000010
    0100110101001001
    1001011010010000
    '''.strip().split()),
    ('''
    1111000011111111
    0111111111011111
    0100001010001001
    1111111111111110
    '''.strip().split(),
    '''
    0000100000001000
    0010010010110010
    1001100100001010
    '''.strip().split())
]
texture_cache = {}

class BossScript():
    def __init__(self, system, x, y):
        self.system = system
        self.x = x
        self.y = y
        self.ticks = 0
        self.coroutines = CoroutineSystem([self.main()])

    def main(self):
        pass

    def tick(self):
        self.coroutines.tick()
        self.ticks += 1

class BossScriptPhase1(BossScript):
    def __init__(self, system, x, y):
        super().__init__(system, x, y)

    def main(self):
        self.coroutines.add(self.rings())
        self.coroutines.add(self.maze_guide())
        self.coroutines.add(self.maze())
        while True:
            yield from sleep_ticks(1)

    def maze_guide(self):
        self.system.shoot(RectMazeGuideBullet(self.system, 640, 1280, 640, 30+96, 1280, 16))
        self.system.shoot(RectMazeGuideBullet(self.system, 0, 640, 640-48, 640, 16, 1280))
        self.system.shoot(RectMazeGuideBullet(self.system, 1280, 640, 640+48, 640, 16, 1280))
        yield from sleep_ticks(60 * 2)
        self.system.shoot(RectMazeOuterWallBullet(self.system, 640 - 96*5.5, 30 + 96*3, 16, 96*6))
        self.system.shoot(RectMazeOuterWallBullet(self.system, 640 + 96*5.5, 30 + 96*3, 16, 96*6))
        self.system.shoot(RectMazeOuterWallBullet(self.system, 640, 30 + 96*6, 96*11, 16))
        self.system.shoot(RectMazeOuterWallBullet(self.system, 640, 30, 96*11, 16))
        yield

    def maze(self):
        mazei = 0
        yield from sleep_ticks(60 * 5)
        angle = 270
        while True:
            for x,y in RECT_MAZES[mazei][0]:
                self.system.shoot(RectMazeBullet(self.system, 640 + 96*(x-5), 30 + 96*y, 96, 16, angle))
            for x,y in RECT_MAZES[mazei][1]:
                self.system.shoot(RectMazeBullet(self.system, 640 + 96*(x-5.5), 30 + 96*(y+0.5), 16, 96, angle))
            yield from sleep_ticks(60 * 10)
            if angle == 270:
                angle = 90
            else:
                angle = 270
            mazei = (mazei+1) % len(RECT_MAZES)


    def rings(self):
        while True:
            angle = self.system.angle_to_player(self.x, self.y)
            for i in range(20):
                self.system.shoot(SimpleBullet(self.system, self.x, self.y, 300, 18*i + angle))
            yield from sleep_ticks(120)

class BossScriptPhase2(BossScript):
    def __init__(self, system, x, y):
        super().__init__(system, x, y)

    def main(self):
        self.coroutines.add(self.rings())
        self.coroutines.add(self.maze_guide())
        self.coroutines.add(self.maze())
        while True:
            yield from sleep_ticks(1)

    def maze_guide(self):
        for i in range(360):
            self.system.shoot(CircMazeGuideBullet(self.system, 640, 380, 50, 1120, i))
        yield

    def maze(self):
        mazei = 0
        while True:
            yield from sleep_ticks(60 * 5)
            for j in range(1,5):
                r = 100*j-50
                for i in range(16):
                    if CIRC_MAZES[mazei][0][j-1][i] == '1':
                        for k in range(5):
                            angle = 4.5*(i*5+k)
                            if (i*5+k)%3 == 0:
                                delete_after_speedup = -1
                            else:
                                delete_after_speedup = int(r/200 * 60)
                            self.system.shoot(CircMazeBullet(self.system, 640 + r*math.cos(math.radians(angle)), 380 + r*math.sin(math.radians(angle)), angle+180, delete_after_speedup))
                    if j != 4 and CIRC_MAZES[mazei][1][j-1][i] == '1':
                        for k in range(6):
                            angle = 4.5*i*5
                            radius = r + 20*k
                            self.system.shoot(CircMazeBullet(self.system, 640 + radius*math.cos(math.radians(angle)), 380 + radius*math.sin(math.radians(angle)), angle+180, -1))
            yield from sleep_ticks(60 * 15)
            mazei = (mazei+1) % len(CIRC_MAZES)

    def rings(self):
        while True:
            angle = self.system.angle_to_player(self.x, self.y)
            for i in range(20):
                self.system.shoot(SimpleBullet(self.system, self.x, self.y, 200, 18*i + angle, hue=0))
            yield from sleep_ticks(60)

class Bullet(arcade.Sprite):
    # note: if hitbox is non-uniform, angle must be 0!
    def __init__(self, system, x, y, speed, angle, radius_x, radius_y, hue, saturation, shape, draw_scale):
        key = self.texture_key(hue, saturation, shape)
        if key in texture_cache:
            texture = texture_cache[key]
        else:
            image = Image.open('resources/objects/bullets.png')
            image = image.crop((BASE_SHAPE_X[shape], 0, BASE_SHAPE_X[shape]+BULLET_SIZE, BULLET_SIZE))
            for i, px in enumerate(image.getdata()):
                alpha = px[3]
                lightness = colorsys.rgb_to_hls(px[0]/255, px[1]/255, px[2]/255)[1]
                xx = i % BULLET_SIZE
                yy = i // BULLET_SIZE
                red, green, blue = [int(n*255) for n in colorsys.hls_to_rgb(hue/360, lightness, saturation)]
                image.putpixel((xx, yy), (red, green, blue, alpha))
            name = f'bullet_{key}'
            texture = arcade.Texture(image=image, name=name, hit_box_algorithm='None')
            texture_cache[key] = texture
        super().__init__(texture=texture, hit_box_algorithm='None')
        self.system = system
        if type(draw_scale) in [list, tuple]:
            scale_x, scale_y = draw_scale
        else:
            scale_x = scale_y = draw_scale
        self.width = BULLET_SIZE * scale_x
        self.height = BULLET_SIZE * scale_y
        self.orig_width = self.width
        self.orig_height = self.height
        self.hitbox_radius_x = radius_x
        self.hitbox_radius_y = radius_y
        self.speed = speed
        self.angle = angle
        self.set_position(x, y)
        self.updater = self.run()
        self.intangible = True
        self.alpha = 0
        self.scale = 0
        self.permanent = False
        self.damage = 50

    @property
    def scale(self):
        return self._scale

    # scale setter that preserves original size
    @scale.setter
    def scale(self, new_value):
        if new_value != self._scale:
            self._scale = new_value
            self._width = self.orig_width * self._scale
            self._height = self.orig_height * self._scale
            for sprite_list in self.sprite_lists:
                sprite_list.update_size(self)

    def texture_key(self, hue, saturation, shape):
        return f'{hue}_{saturation}_{shape}'

    def move_simple(self):
        x, y = self.position
        x += self.speed * constants.TICK_S * math.cos(math.radians(self.angle))
        y += self.speed * constants.TICK_S * math.sin(math.radians(self.angle))
        self.set_position(x, y)

    def spawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * progress)
            self.scale = progress
            yield
        self.intangible = False

    def despawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * (1 - progress))
            self.scale = 1 + progress
            yield
        self.system.destroy(self)
        yield

class RectMazeBullet(Bullet):
    def __init__(self, system, x, y, width, height, angle):
        draw_scale = (width / BULLET_SIZE, height / BULLET_SIZE)
        radius_x = width/2
        radius_y = height/2
        super().__init__(system, x, y, 1, 0, radius_x=radius_x, radius_y=radius_y,
                         hue=60, saturation=1.0, shape='rect', draw_scale=draw_scale)
        self.permanent = True
        self.intangible = False
        self.damage = 500
        self.move_angle = angle

    def spawn_anim(self):
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * progress)
            self.scale = progress
            yield

    def move_simple(self):
        x, y = self.position
        x += self.speed * constants.TICK_S * math.cos(math.radians(self.move_angle))
        y += self.speed * constants.TICK_S * math.sin(math.radians(self.move_angle))
        self.set_position(x, y)

    def run(self):
        yield from self.spawn_anim()
        for i in range(60 * 10 - 10):
            self.move_simple()
            yield
        self.speed = 200
        self.permanent = False
        while True:
            self.move_simple()
            yield

class RectMazeGuideBullet(Bullet):
    def __init__(self, system, x1, y1, x2, y2, width, height):
        draw_scale = (width / BULLET_SIZE, height / BULLET_SIZE)
        radius_x = width/2
        radius_y = height/2
        super().__init__(system, x1, y1, 0, 0, radius_x=radius_x, radius_y=radius_y,
                         hue=30, saturation=1.0, shape='rect', draw_scale=draw_scale)
        self.permanent = True
        self.intangible = False
        self.damage = 500
        self.x1 = x1
        self.y1 = y1
        self.x2 = x2
        self.y2 = y2
        self.alpha = 255
        self.scale = 1

    def run(self):
        i = 0
        for i in range(60*5):
            progress = i / (60*5-1)
            x = self.x1 + (self.x2-self.x1)*progress
            y = self.y1 + (self.y2-self.y1)*progress
            self.set_position(x, y)
            yield
        self.system.despawn(self)
        yield

class RectMazeOuterWallBullet(Bullet):
    def __init__(self, system, x, y, width, height):
        draw_scale = (width / BULLET_SIZE, height / BULLET_SIZE)
        radius_x = width/2
        radius_y = height/2
        super().__init__(system, x, y, 1, 0, radius_x=radius_x, radius_y=radius_y,
                         hue=30, saturation=1.0, shape='rect', draw_scale=draw_scale)
        self.permanent = True
        self.intangible = False
        self.damage = 500

    def spawn_anim(self):
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * progress)
            self.scale = progress
            yield

    def run(self):
        yield from self.spawn_anim()
        while True:
            yield

class SimpleBullet(Bullet):
    def __init__(self, system, x, y, speed, angle, hue=60, saturation=1.0, shape='oval', scale=1):
        base_shape, scale_x, scale_y, hitbox_mult = SHAPES[shape]
        draw_scale = (scale_x * scale, scale_y * scale)
        radius_x = BULLET_SIZE/2 * scale * hitbox_mult
        radius_y = BULLET_SIZE/2 * scale * hitbox_mult
        super().__init__(system, x, y, speed, angle, radius_x=radius_x, radius_y=radius_y,
                         hue=hue, saturation=saturation, shape=base_shape, draw_scale=draw_scale)

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.move_simple()
            yield


class CircMazeBullet(SimpleBullet):
    def __init__(self, system, x, y, angle, delete_after_speedup):
        super().__init__(system, x, y, 1, angle, hue=60, shape='arrow')
        self.permanent = True
        self.intangible = False
        self.delete_after_speedup = delete_after_speedup
        self.damage = 500

    def spawn_anim(self):
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * progress)
            self.scale = progress
            yield

    def run(self):
        yield from self.spawn_anim()
        for i in range(60 * 15):
            self.move_simple()
            yield
        self.speed = 200
        self.permanent = False
        if self.delete_after_speedup == -1:
            while True:
                self.move_simple()
                yield
        else:
            for i in range(self.delete_after_speedup):
                self.move_simple()
                yield
        self.system.despawn(self)
        yield

class CircMazeGuideBullet(SimpleBullet):
    def __init__(self, system, x, y, rmin, rmax, angle):
        super().__init__(system, x - rmax*math.cos(math.radians(angle)), y - rmax*math.sin(math.radians(angle)), 0, angle, hue=120, shape='arrow')
        self.permanent = True
        self.intangible = False
        self.alpha = 255
        self.scale = 1
        self.damage = 500
        self.rmin = rmin
        self.rrange = rmax-rmin
        self.centerx = x
        self.centery = y

    def move_r(self, progress):
        r = (self.rmin + self.rrange*progress)
        x = self.centerx - r*math.cos(math.radians(self.angle))
        y = self.centery - r*math.sin(math.radians(self.angle))
        self.set_position(x, y)

    def run(self):
        i = 0
        while True:
            for i in range(60*5):
                progress = 1 - (i / (60*5-1))
                self.move_r(progress)
                yield
            for i in range(60):
                progress = i / (60-1)
                self.move_r(progress)
                yield
            yield from sleep_ticks(60 * 14)


class PlayerBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle):
        super().__init__(system, x, y, speed, angle, hue=60, saturation=1.0, shape='arrow', scale=1)
        self.intangible = False
        self.alpha = 255
        self.scale = 1

    def despawn_anim(self):
        self.intangible = True
        for i in range(10):
            progress = (i / (10 - 1)) ** 2
            self.alpha = int(255 * (1 - progress))
            self.scale = 1 + progress
            yield
        self.system.player_destroy(self)
        yield

    def run(self):
        while True:
            self.move_simple()
            yield
