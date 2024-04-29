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
import math
from collections import deque

import arcade
import constants
from components import danmaku

PLAYER_HITBOX_RADIUS = 5
MARGIN = 50
BOSS_FLASH_LEN = 3
BOSS_FLASH_MAX_COOLDOWN = 6
INTRO_LEN = 180
BOSS_TITLE = 'villAIn Mk.I "Example Boss"'
HEALTHBAR_LEN = 1240


# arcade.create_rectangle_filled, but it allows changing the color
class DrawableRectLRTB:
    def __init__(self, l, r, t, b, color):
        self.l = l
        self.r = r
        self.t = t
        self.b = b
        self.color = color

    def draw(self):
        arcade.draw_lrtb_rectangle_filled(self.l, self.r, self.t, self.b, self.color)


class DanmakuSystem:
    def __init__(self, player, boss, is_server):
        self.boss = boss
        if not self.boss.destructing:
            self.boss.sprite.set_animation("bwahaha")
        self.boss_hitbox = [self.boss.x - 295, self.boss.x + 295, self.boss.y - 278,
                            self.boss.y + 300]  # lrbt
        self.boss_max_health = 1000
        self.boss_health = self.boss_max_health
        self.player = player
        self.ticks = 0
        self.player_bullets = arcade.SpriteList(lazy=True, capacity=50)
        self.player_bullets.alpha = 100
        self.bullets = arcade.SpriteList(lazy=True, capacity=1000)
        self.to_add = deque()
        self.to_remove = deque()
        self.player_to_add = deque()
        self.player_to_remove = deque()
        self.boss_flash_time = 0
        self.boss_flash_cooldown = 0
        self.is_server = is_server
        if not self.is_server:
            self.gui = {}
            self.gui["boss_title_background"] = DrawableRectLRTB(0, 1280, 1280, 1180,
                                                                 color=(0, 0, 0, 0))
            self.gui["boss_health"] = DrawableRectLRTB(640 - HEALTHBAR_LEN // 2,
                                                       640 + HEALTHBAR_LEN // 2, 1210,
                                                       1190, color=(255, 0, 0, 0))
            self.gui["boss_title"] = arcade.Text(BOSS_TITLE, 640, 1240, font_size=36,
                                                 color=(255, 255, 255, 0),
                                                 font_name=constants.FONT_NAME,
                                                 anchor_x="center", anchor_y="center")
            self.gui["warning_background"] = DrawableRectLRTB(0, 1280, 640 + 150,
                                                              640 - 150,
                                                              color=(0, 0, 0, 0))
            self.gui["warning1"] = arcade.Text(
                "WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING", 640,
                640 + 120, color=(255, 0, 0, 0), font_size=36,
                font_name=constants.FONT_NAME, anchor_x="center", anchor_y="center")
            self.gui["warning2"] = arcade.Text(
                'WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING', 640,
                640 - 120 - 6, color=(255, 0, 0, 0), font_size=36,
                font_name=constants.FONT_NAME, anchor_x="center", anchor_y="center")
            self.gui["warning_title"] = arcade.Text("", 640, 640 - 3,
                                                    color=(255, 255, 255, 255),
                                                    font_size=36,
                                                    font_name=constants.FONT_NAME,
                                                    anchor_x="center",
                                                    anchor_y="center")

    def draw(self):
        self.player_bullets.draw()
        self.bullets.draw()

    def _draw(self):
        arcade.draw_rectangle_filled(self.player.x, self.player.y,
                                     PLAYER_HITBOX_RADIUS * 2, PLAYER_HITBOX_RADIUS * 2,
                                     (255, 0, 255))
        for bullet in self.bullets:
            if not bullet.intangible:
                arcade.draw_rectangle_outline(bullet.position[0], bullet.position[1],
                                              bullet.hitbox_radius * 2,
                                              bullet.hitbox_radius * 2, (255, 0, 0))
        arcade.draw_lrtb_rectangle_outline(self.boss_hitbox[0], self.boss_hitbox[1],
                                           self.boss_hitbox[3], self.boss_hitbox[2],
                                           (255, 0, 255))

    def draw_gui(self):
        boss_health_percent = max(0, self.boss_health / self.boss_max_health)
        if boss_health_percent > 0:
            self.gui["boss_health"].r = self.gui[
                                            "boss_health"].l + boss_health_percent * HEALTHBAR_LEN
        else:
            self.gui["boss_health"].color = (0, 0, 0, 0)
        for elem in self.gui:
            self.gui[elem].draw()

    def tick(self, pressed_keys):
        if self.ticks < INTRO_LEN and not self.boss.destructing:
            if not self.is_server:
                if self.ticks < 30:
                    progress = self.ticks / 29
                    self.gui["warning_background"].color = (
                    0, 0, 0, int(128 * progress))
                    self.gui["warning1"].color = (255, 0, 0, int(255 * progress))
                    self.gui["warning2"].color = (255, 0, 0, int(255 * progress))
                elif self.ticks < 120:
                    progress = (self.ticks - 30) / 89
                    type_len = 1 + int(progress * len(BOSS_TITLE))
                    if type_len != len(self.gui["warning_title"].text):
                        self.gui["warning_title"].text = BOSS_TITLE[:type_len]
                elif self.ticks >= 150:
                    progress = (self.ticks - 150) / 29
                    self.gui["warning_background"].color = (
                    0, 0, 0, int(128 * (1 - progress)))
                    self.gui["warning1"].color = (200, 0, 0, int(255 * (1 - progress)))
                    self.gui["warning2"].color = (255, 0, 0, int(255 * (1 - progress)))
                    self.gui["warning_title"].color = (
                    255, 255, 255, int(255 * (1 - progress)))
                    self.gui["boss_title_background"].color = (
                    0, 0, 0, int(128 * progress))
                    self.gui["boss_title"].color = (255, 255, 255, int(255 * progress))
                    self.gui["boss_health"].color = (255, 0, 0, int(255 * progress))
                self.gui["warning1"].x += 2
                self.gui["warning2"].x -= 2
        else:
            if not self.boss.destructing:
                if not self.player.dead and arcade.key.SPACE in pressed_keys and self.ticks % 3 == 0:
                    self.player_shoot(danmaku.PlayerBullet(self, self.player.x - 18,
                                                           self.player.y + 20, 4000,
                                                           90))
                    self.player_shoot(danmaku.PlayerBullet(self, self.player.x + 18,
                                                           self.player.y + 20, 4000,
                                                           90))
                if self.boss_health > 0:
                    if self.ticks % 30 == 0:
                        self.shoot(danmaku.SimpleBullet(self, 640, 870, 200,
                                                        self.angle_to_player(640, 870)))
                else:
                    self.boss.destruct()
                    self.despawn_all(self.bullets)
            for bullet in self.bullets:
                next(bullet.updater)
            for bullet in self.player_bullets:
                next(bullet.updater)
            self.check_collisions()
            self.check_oob()
            while len(self.to_add) > 0:
                self.bullets.append(self.to_add.pop())
            while len(self.to_remove) > 0:
                self.to_remove.pop().kill()
            while len(self.player_to_add) > 0:
                self.player_bullets.append(self.player_to_add.pop())
            while len(self.player_to_remove) > 0:
                self.player_to_remove.pop().kill()
            self.boss_flash_cooldown = max(0, self.boss_flash_cooldown - 1)
            if self.boss_flash_time == 1 and not self.boss.destructing:
                self.boss.sprite.set_animation("bwahaha2")
            self.boss_flash_time = max(0, self.boss_flash_time - 1)
        self.ticks += 1

    def angle_to_player(self, x, y):
        return math.degrees(math.atan2(self.player.y - y, self.player.x - x))

    def shoot(self, bullet):
        if not self.boss.destructing:
            self.to_add.append(bullet)

    def player_shoot(self, bullet):
        self.player_to_add.append(bullet)

    @staticmethod
    def despawn(bullet):
        bullet.updater = bullet.despawn_anim()

    @staticmethod
    def despawn_all(bullets):
        for bullet in bullets:
            bullet.updater = bullet.despawn_anim()

    def destroy(self, bullet):
        self.to_remove.append(bullet)

    def player_destroy(self, bullet):
        self.player_to_remove.append(bullet)

    def check_collisions(self):
        px = self.player.x
        py = self.player.y
        for bullet in self.bullets:
            if (not bullet.intangible and
                    px - PLAYER_HITBOX_RADIUS < bullet.position[
                        0] + bullet.hitbox_radius and
                    px + PLAYER_HITBOX_RADIUS > bullet.position[
                        0] - bullet.hitbox_radius and
                    py - PLAYER_HITBOX_RADIUS < bullet.position[
                        1] + bullet.hitbox_radius and
                    py + PLAYER_HITBOX_RADIUS > bullet.position[
                        1] - bullet.hitbox_radius):
                self.player.decrease_health(1)
                if self.player.dead:
                    self.despawn_all(self.player_bullets)
                else:
                    self.player.sprite.set_flashing(True)
                self.despawn(bullet)

        for bullet in self.player_bullets:
            if (not bullet.intangible and
                    self.boss_hitbox[0] < bullet.position[0] + bullet.hitbox_radius and
                    self.boss_hitbox[1] > bullet.position[0] - bullet.hitbox_radius and
                    self.boss_hitbox[2] < bullet.position[1] + bullet.hitbox_radius and
                    self.boss_hitbox[3] > bullet.position[1] - bullet.hitbox_radius):
                self.boss_health -= 1
                if self.boss_flash_cooldown == 0 and not self.boss.destructing:
                    self.boss_flash_cooldown = BOSS_FLASH_MAX_COOLDOWN
                    self.boss_flash_time = BOSS_FLASH_LEN
                    self.boss.sprite.set_animation("damage")
                self.despawn(bullet)

    def check_oob(self):
        for bullet in self.bullets:
            x, y = bullet.position
            if x < 0 - MARGIN or x > 1280 + MARGIN or y < 0 - MARGIN or y > 1280 + MARGIN:
                self.destroy(bullet)
        for bullet in self.player_bullets:
            x, y = bullet.position
            if x < 0 - MARGIN or x > 1280 + MARGIN or y < 0 - MARGIN or y > 1280 + MARGIN:
                self.player_destroy(bullet)
        # i don't know how you clipped oob, but please don't do that
        if self.player.x <= 0 or self.player.x >= 1280 or self.player.y <= 0 or self.player.y >= 1280:
            self.player.decrease_health(200)
