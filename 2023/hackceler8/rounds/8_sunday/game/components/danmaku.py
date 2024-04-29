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
texture_cache = {}

class BossScript():
    def __init__(self, system, x, y):
        self.system = system
        self.x = x
        self.y = y
        self.ticks = 0
        self.coroutines = CoroutineSystem([self.main()])
        self.angle = 0
        self.angle_accel = 0

    def main(self):
        self.coroutines.add(self.bowap())
        while True:
            yield from sleep_ticks(1)

    # border of wave and particle
    def bowap(self):
        while True:
            for i in range(10):
                self.system.shoot(SimpleBullet(self.system, self.x, self.y, 400, angle=self.angle + i*36, hue=120))
            self.angle_accel += 0.234
            self.angle += self.angle_accel
            yield from sleep_ticks(2)

    def squares(self):
        while True:
            self.system.shoot(SimpleBullet(self.system, (self.ticks * 25) % 1280, 1280, 300, angle=270, hue=60, shape='rect', scale=4))
            yield from sleep_ticks(30)

    def reflect(self):
        while True:
            for i in range(10):
                self.system.shoot(ReflectBullet(self.system, self.x, self.y, 200, angle=(self.ticks/120 * 12.5) + i*36, scale=2))
            yield from sleep_ticks(120)

    def lasers(self):
        while True:
            for j in range(3):
                for i in range(5):
                    self.system.shoot(LaserBullet(self.system, self.x, self.y, 150, angle=(self.ticks * 0.125) + i*72, av=0.125, hue=240, scale=1))
                yield from sleep_ticks(10)
            for j in range(3):
                for i in range(5):
                    self.system.shoot(LaserBullet(self.system, self.x, self.y, 150, angle=(self.ticks * -0.125) + i*72, av=-0.125, hue=300, scale=1))
                yield from sleep_ticks(10)

    def new_phase(self, phase):
        if phase == 2:
            self.coroutines.add(self.lasers())
        elif phase == 3:
            self.coroutines.add(self.reflect())
        elif phase == 4:
            self.coroutines.add(self.squares())

    def tick(self):
        self.coroutines.tick()
        self.ticks += 1

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

class ReflectBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle, hue=180, saturation=1.0, shape='arrow', scale=1,
                 max_bounces=1):
        super().__init__(system, x, y, speed, angle, hue=hue, saturation=saturation, shape=shape,
                         scale=scale)
        self.max_bounces = max_bounces
        self.bounces = 0

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.move_simple()
            x, y = self.position
            if x < 0 or x > 1280: # left/right
                if self.bounces < self.max_bounces:
                    self.angle = 180-self.angle
                self.bounces += 1
            elif y < 0 or y > 1280: # bottom/top
                if self.bounces < self.max_bounces:
                    self.angle = -self.angle
                self.bounces += 1
            yield

class LaserBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle, hue=240, saturation=1.0, shape='circle', av=0.125, scale=1):
        super().__init__(system, x, y, speed, angle, hue=hue, saturation=saturation, shape=shape,
                         scale=scale)
        self.radius = 0
        self.av = av
        self.base_x = x
        self.base_y = y

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.radius += self.speed * constants.TICK_S
            x = self.base_x + self.radius * math.cos(math.radians(self.angle))
            y = self.base_y + self.radius * math.sin(math.radians(self.angle))
            self.set_position(x, y)
            self.angle += self.av
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
