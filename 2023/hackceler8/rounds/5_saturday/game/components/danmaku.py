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
    'rotrect': ('rect', 0.5, 0.5, 0.5 * 0.6),
    'arrow': ('arrow', 0.5, 0.5, 0.25),
    'oval': ('circle', 0.5, 0.25, 0.175),
}
CUBES2 = [[int(j) for j in i] for i in '''
044533425153405132011202
151222430523314045410503
110422433351525005412403
253154400433534121012502
001345412250513323414205
352221405044115540213303
'''.strip().splitlines()]
PERM2 = {
    'U': [(0,1,3,2), (17,13,9,5), (16,12,8,4)],
    'F': [(8,9,11,10), (2,12,21,7), (3,14,20,5)],
    'R': [(12,13,15,14), (3,16,23,11), (1,18,21,9)],
}
CUBES3 = [[int(j) for j in i] for i in '''
450154430003241542543233121452025211311210533035004254
311355553022041243112435231530224514404312540004502103
441152322040042534211332314552020143001113544055503352
411051025043542042452333301144021043521513412522503305
'''.strip().splitlines()]
PERM3 = {
    'U': [(1,5,7,3), (0,2,8,6), (19,10,37,28), (18,9,36,27), (20,11,38,29)],
    'D': [(46,50,52,48), (45,47,53,51), (25,34,43,16), (26,35,44,17), (24,33,42,15)],
    'F': [(19,23,25,21), (18,20,26,24), (7,30,46,14), (8,33,45,11), (6,27,47,17)],
    'B': [(37,41,43,39), (36,38,44,42), (1,12,52,32), (2,9,51,35), (0,15,53,29)],
    'R': [(28,32,34,30), (27,29,35,33), (23,5,39,50), (8,36,53,26), (20,2,42,47)],
    'L': [(10,14,16,12), (11,17,15,9), (3,21,48,41), (6,24,51,38), (0,18,45,44)],
}
FACE_COLORS = [
    (0, 0.0), # white
    (30, 1.0), # orange
    (120, 1.0), # green
    (0, 1.0), # red
    (240, 1.0), # blue
    (60, 1.0), # yellow
]
BASE_Y = 1280-180
FACE_SIZE = 120
CENTERS = [
    (640 - FACE_SIZE*0.5, BASE_Y+FACE_SIZE),
    (640 - FACE_SIZE*1.5, BASE_Y),
    (640 - FACE_SIZE*0.5, BASE_Y),
    (640 + FACE_SIZE*0.5, BASE_Y),
    (640 + FACE_SIZE*1.5, BASE_Y),
    (640 - FACE_SIZE*0.5, BASE_Y-FACE_SIZE)
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
        self.cube_faces = []

    def main(self):
        self.coroutines.add(self.cube())
        self.coroutines.add(self.squares())
        self.coroutines.add(self.bigfan())
        while True:
            yield from sleep_ticks(1)

    def cube(self):
        cubei = 0
        delay = 60*20
        while True:
            self.cube_faces = []
            for face in range(6):
                for i in range(4):
                    x = CENTERS[face][0] + ((i%2)-0.5)*FACE_SIZE/2
                    y = CENTERS[face][1] - ((i//2)-0.5)*FACE_SIZE/2
                    bullet = CubeFaceBullet(self.system, x, y, FACE_SIZE/2, FACE_SIZE/2, CUBES2[cubei][face*4+i], delay=delay)
                    self.cube_faces.append(bullet)
                    self.system.shoot(bullet)
            cube_laser = CubeFaceBullet(self.system, 640, BASE_Y, 1280, FACE_SIZE*3, 0, delay=delay)
            self.cube_faces.append(cube_laser)
            self.system.shoot(cube_laser)
            yield from sleep_ticks(delay)
            cubei = (cubei+1) % len(CUBES2)

    def squares(self):
        cy = 1000
        colori = 0
        while True:
            cx = self.system.player.x
            hue, saturation = FACE_COLORS[colori]
            for row in range(5):
                for col in range(5):
                    dx = (row-2)*100
                    dy = (col-2)*100
                    theta = math.degrees(math.atan2(dy, dx))
                    radius = math.hypot(dx, dy)
                    self.system.shoot(SquareBullet(self.system, cx, cy, 100, theta, radius, hue, saturation))
            colori = (colori+1)%6
            yield from sleep_ticks(60 * 6)

    def bigfan(self):
        cy = 1000
        colori = 0
        while True:
            cx = self.system.player.x
            hue, saturation = FACE_COLORS[colori]
            for i in range(27):
                angle = 90 + 12*(i-13)
                self.system.shoot(SimpleBullet(self.system, self.x, self.y, 400, angle, hue, saturation))
            colori = (colori+1)%6
            yield from sleep_ticks(10)

    def rotate(self, rotation):
        if len(self.cube_faces) < 6*4:
            return
        for perm in PERM2[rotation]:
            # position
            tmp = self.cube_faces[perm[0]].position
            for i in range(len(perm)-1):
                self.cube_faces[perm[i]].set_position(*self.cube_faces[perm[i+1]].position)
            self.cube_faces[perm[-1]].set_position(*tmp)
            # index
            tmp = self.cube_faces[perm[-1]]
            for i in range(len(perm)-1)[::-1]:
                self.cube_faces[perm[i+1]] = self.cube_faces[perm[i]]
            self.cube_faces[perm[0]] = tmp
        colors = [bullet.face_color for bullet in self.cube_faces]
        for face in range(0, 6*4, 4):
            if not (colors[face+0] == colors[face+1] == colors[face+2] == colors[face+3]):
                return
        for bullet in self.cube_faces:
            self.system.despawn(bullet)
        self.cube_faces = []

class BossScriptPhase2(BossScript):
    def __init__(self, system, x, y):
        super().__init__(system, x, y)
        self.cube_faces = []

    def main(self):
        self.coroutines.add(self.cube())
        self.coroutines.add(self.squares())
        self.coroutines.add(self.bigfan())
        while True:
            yield from sleep_ticks(1)

    def cube(self):
        cubei = 0
        delay = 60*40
        while True:
            self.cube_faces = []
            for face in range(6):
                for i in range(9):
                    x = CENTERS[face][0] + ((i%3)-1)*FACE_SIZE/3
                    y = CENTERS[face][1] - ((i//3)-1)*FACE_SIZE/3
                    bullet = CubeFaceBullet(self.system, x, y, FACE_SIZE/3, FACE_SIZE/3, CUBES3[cubei][face*9+i], delay=delay)
                    self.cube_faces.append(bullet)
                    self.system.shoot(bullet)
            cube_laser = CubeFaceBullet(self.system, 640, BASE_Y, 1280, FACE_SIZE*3, 0, delay=delay)
            self.cube_faces.append(cube_laser)
            self.system.shoot(cube_laser)
            yield from sleep_ticks(delay)
            cubei = (cubei+1) % len(CUBES3)

    def squares(self):
        cy = 1000
        colori = 0
        while True:
            cx = self.system.player.x
            hue, saturation = FACE_COLORS[colori]
            for row in range(9):
                for col in range(9):
                    dx = (row-4)*100
                    dy = (col-4)*100
                    theta = math.degrees(math.atan2(dy, dx))
                    radius = math.hypot(dx, dy)
                    self.system.shoot(SquareBullet(self.system, cx, cy, 100, theta, radius, hue, saturation))
            colori = (colori+1)%6
            yield from sleep_ticks(60 * 10)

    def bigfan(self):
        cy = 1000
        colori = 0
        while True:
            cx = self.system.player.x
            hue, saturation = FACE_COLORS[colori]
            for i in range(27):
                angle = 90 + 12*(i-13)
                self.system.shoot(SimpleBullet(self.system, self.x, self.y, 400, angle, hue, saturation, scale=2))
            colori = (colori+1)%6
            yield from sleep_ticks(10)

    def rotate(self, rotation):
        if len(self.cube_faces) < 6*9:
            return
        for perm in PERM3[rotation]:
            # position
            tmp = self.cube_faces[perm[0]].position
            for i in range(len(perm)-1):
                self.cube_faces[perm[i]].set_position(*self.cube_faces[perm[i+1]].position)
            self.cube_faces[perm[-1]].set_position(*tmp)
            # index
            tmp = self.cube_faces[perm[-1]]
            for i in range(len(perm)-1)[::-1]:
                self.cube_faces[perm[i+1]] = self.cube_faces[perm[i]]
            self.cube_faces[perm[0]] = tmp
        colors = [bullet.face_color for bullet in self.cube_faces]
        for face in range(0, 6*9, 9):
            if not (colors[face+0] == colors[face+1] == colors[face+2] == colors[face+3] ==
                    colors[face+4] == colors[face+5] == colors[face+6] == colors[face+7] ==
                    colors[face+8]):
                return
        for bullet in self.cube_faces:
            self.system.despawn(bullet)
        self.cube_faces = []

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

class CubeFaceBullet(Bullet):
    def __init__(self, system, x, y, width, height, face_color, delay):
        draw_scale = (width / BULLET_SIZE, height / BULLET_SIZE)
        radius_x = width/2
        radius_y = height/2
        hue, saturation = FACE_COLORS[face_color]
        super().__init__(system, x, y, 200, 0, radius_x=radius_x, radius_y=radius_y,
                         hue=hue, saturation=saturation, shape='rect', draw_scale=draw_scale)
        self.permanent = True
        self.intangible = False
        self.damage = 500
        self.move_angle = 270
        self.face_color = face_color
        self.delay = delay

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
        for i in range(60 * 3 - 10):
            self.move_simple()
            yield
        for i in range(self.delay - 60*3):
            yield
        self.speed = 400
        self.permanent = False
        while True:
            self.move_simple()
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

class SquareBullet(SimpleBullet):
    def __init__(self, system, cx, cy, speed, theta, radius, hue, saturation):
        super().__init__(system, cx, cy, speed, 0, hue=hue, saturation=saturation, shape='rotrect', scale=0.5)
        self.cx = cx
        self.cy = cy
        self.radius = radius
        self.cur_radius_mult = 0
        self.theta = theta

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.cy -= self.speed * constants.TICK_S
            if self.cur_radius_mult < 1:
                self.cur_radius_mult += 0.005
            self.angle += 0.2
            self.theta += 0.2
            x = self.cx + self.cur_radius_mult * self.radius * math.cos(math.radians(self.theta))
            y = self.cy + self.cur_radius_mult * self.radius * math.sin(math.radians(self.theta))
            self.set_position(x, y)
            yield

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
