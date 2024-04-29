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

    def main(self):
        pass

    def tick(self):
        self.coroutines.tick()
        self.ticks += 1

class BossScriptPhase1(BossScript):
    def __init__(self, system, x, y):
        super().__init__(system, x, y)

    def main(self):
        self.coroutines.add(self.anomaly())
        self.coroutines.add(self.aimed())
        self.coroutines.add(self.reflect())
        self.coroutines.add(self.above())
        while True:
            yield from sleep_ticks(1)

    def aimed(self):
        while True:
            angle = self.system.angle_to_player(self.x, self.y)
            for i in range(20):
                self.system.shoot(AimedBullet(self.system, self.x, self.y, 300, 18*i + angle, decay_mult=0.98, final_speed=300))
            yield from sleep_ticks(30)

    def reflect(self):
        while True:
            for i in range(5):
                self.system.shoot(ReflectBullet(self.system, self.x, self.y, 300, 30*(i-2) + 90, scale=3))
            yield from sleep_ticks(60 * 5)

    def above(self):
        while True:
            for i in range(41):
                self.system.shoot(AnomalyBullet(self.system, self.x, self.y, 300, 3*(i-20) + 90))
            yield from sleep_ticks(30)

    def anomaly(self):
        while True:
            yield from sleep_ticks(60 * 6)
            self.system.bullet_speed_multiplier = -0.25
            self.system.player.anomaly_speed_multiplier = 0
            self.system.anomaly()
            yield from sleep_ticks(60 * 2)
            self.system.bullet_speed_multiplier = 1
            self.system.player.anomaly_speed_multiplier = 1

class BossScriptPhase2(BossScript):
    def __init__(self, system, x, y):
        super().__init__(system, x, y)
        self.system.bullet_speed_multiplier = 1
        self.system.player.anomaly_speed_multiplier = 1

    def main(self):
        self.coroutines.add(self.anomaly())
        self.coroutines.add(self.aimed())
        self.coroutines.add(self.reflect())
        self.coroutines.add(self.above())
        while True:
            yield from sleep_ticks(1)

    def aimed(self):
        angle = 0
        while True:
            for i in range(6):
                self.system.shoot(AimedBullet(self.system, self.x, self.y, 300, 60*i + angle, decay_mult=0.95, final_speed=300))
            angle = (angle+18) % 360
            yield from sleep_ticks(30)

    def reflect(self):
         while True:
            for i in range(5):
                self.system.shoot(ReflectBullet(self.system, self.x, self.y, 300, 30*(i-2) + 90, scale=3))
            yield from sleep_ticks(60 * 5)

    def above(self):
         while True:
            for i in range(41):
                self.system.shoot(AnomalyBullet(self.system, self.x, self.y, 300, 3*(i-20) + 90, scale=2))
            yield from sleep_ticks(30)

    def anomaly(self):
        while True:
            yield from sleep_ticks(60 * 6)
            self.system.bullet_speed_multiplier = -0.25
            self.system.player.anomaly_speed_multiplier = 0
            for bullet in self.system.bullets:
                if not isinstance(bullet, AnomalyBullet):
                    x, y = bullet.position
                    speed = max(100, bullet.speed)
                    angle = bullet.angle
                    if isinstance(bullet, ReflectBullet):
                        shape = 'circle'
                        scale = 3
                    elif isinstance(bullet, AimedBullet):
                        shape = 'oval'
                        scale = 1
                    for i in range(3):
                        self.system.shoot(AnomalyBullet(self.system, x, y, speed, angle + i*120, shape, scale, apply_anomaly=True))
                    self.system.despawn(bullet)
            self.system.anomaly()
            yield from sleep_ticks(60 * 2)
            self.system.bullet_speed_multiplier = 1
            self.system.player.anomaly_speed_multiplier = 1

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
        x += self.speed * self.system.bullet_speed_multiplier * constants.TICK_S * math.cos(math.radians(self.angle))
        y += self.speed * self.system.bullet_speed_multiplier * constants.TICK_S * math.sin(math.radians(self.angle))
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

class AnomalyBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle, shape='oval', scale=1, apply_anomaly=False):
        super().__init__(system, x, y, speed, angle, hue=0, saturation=0.0, shape=shape, scale=scale)
        self.apply_anomaly = apply_anomaly

    def move_simple(self):
        x, y = self.position
        speed_mult = self.system.bullet_speed_multiplier if self.apply_anomaly else 1
        x += self.speed * speed_mult * constants.TICK_S * math.cos(math.radians(self.angle))
        y += self.speed * speed_mult * constants.TICK_S * math.sin(math.radians(self.angle))
        self.set_position(x, y)

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.move_simple()
            yield

class AimedBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle, decay_mult, final_speed):
        super().__init__(system, x, y, speed, angle)
        self.decay_mult = decay_mult
        self.final_speed = final_speed

    def run(self):
        yield from self.spawn_anim()
        for i in range(60):
            self.move_simple()
            self.speed *= self.decay_mult
            yield
        self.speed = self.final_speed
        x, y = self.position
        self.angle = self.system.angle_to_player(x, y)
        while True:
            self.move_simple()
            yield

class ReflectBullet(SimpleBullet):
    def __init__(self, system, x, y, speed, angle, hue=180, saturation=1.0, shape='circle', scale=1):
        super().__init__(system, x, y, speed, angle, hue=hue, saturation=saturation, shape=shape,
                         scale=scale)

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.move_simple()
            x, y = self.position
            if x < 0 or x > 1280: # left/right
                self.angle = 180-self.angle
            elif y > 1280: # top
                self.angle = -self.angle
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

    def move_simple(self):
        x, y = self.position
        x += self.speed * self.system.player.anomaly_speed_multiplier * constants.TICK_S * math.cos(math.radians(self.angle))
        y += self.speed * self.system.player.anomaly_speed_multiplier * constants.TICK_S * math.sin(math.radians(self.angle))
        self.set_position(x, y)

    def run(self):
        while True:
            self.move_simple()
            yield
