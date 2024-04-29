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
from engine.coroutines import CoroutineSystem, sleep_ticks

PLAYER_HITBOX_RADIUS = 5
MARGIN = 50
BOSS_FLASH_LEN = 3
BOSS_FLASH_MAX_COOLDOWN = 6
BOSS_TITLE = 'rAIbbit Mk.III "Cubic Type Theory"'
HEALTHBAR_LEN = 1240
ROTATOR_RADIUS = 32
ROTATORS = {
    'U': (540, 200),
    'D': (540, 100),
    'F': (640, 200),
    'B': (640, 100),
    'R': (740, 200),
    'L': (740, 100),
}

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
        self.boss_max_health = 3500
        self.boss_health = self.boss_max_health
        self.boss_phase = 1
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
        self.focusing = False
        if not self.is_server:
            self.gui = {}
            self.gui["boss_title_background"] = DrawableRectLRTB(0, 1280, 1280, 1180,
                                                                 color=(0, 0, 0, 0))
            self.gui["boss_health"] = DrawableRectLRTB(640 - HEALTHBAR_LEN // 2,
                                                       640 + HEALTHBAR_LEN // 2, 1210,
                                                       1190, color=(255, 0, 0, 0))
            self.gui["phase_marker"] = DrawableRectLRTB(640 - 1, 640 + 1, 1215,
                                                     1185, color=(255, 255, 255, 0))
            self.gui["boss_title"] = arcade.Text(BOSS_TITLE, 640, 1240, font_size=36,
                                                 color=(255, 255, 255, 0),
                                                 font_name=constants.FONT_NAME,
                                                 anchor_x="center", anchor_y="center")
            self.gui["warning_background"] = DrawableRectLRTB(0, 1280, 640 + 150,
                                                              640 - 150,
                                                              color=(0, 0, 0, 0))
            self.gui["warning1"] = arcade.Text(
                "WARNING "*7, 640,
                640 + 120, color=(255, 0, 0, 0), font_size=36,
                font_name=constants.FONT_NAME, anchor_x="center", anchor_y="center")
            self.gui["warning2"] = arcade.Text(
                "WARNING "*7, 640,
                640 - 120 - 6, color=(255, 0, 0, 0), font_size=36,
                font_name=constants.FONT_NAME, anchor_x="center", anchor_y="center")
            self.gui["warning_title"] = arcade.Text("", 640, 640 - 3,
                                                    color=(255, 255, 255, 255),
                                                    font_size=36,
                                                    font_name=constants.FONT_NAME,
                                                    anchor_x="center",
                                                    anchor_y="center")
            for rot in ROTATORS:
                x,y = ROTATORS[rot]
                l = x-ROTATOR_RADIUS
                r = x+ROTATOR_RADIUS
                t = y+ROTATOR_RADIUS
                b = y-ROTATOR_RADIUS
                color = (255, 0, 0, 64) if rot in 'UFR' else (255, 0, 0, 0)
                textcolor = (255, 255, 255, 64) if rot in 'UFR' else (255, 255, 255, 0)
                self.gui["rot_"+rot] = DrawableRectLRTB(l, r, t, b, color=color)
                self.gui["rot_"+rot+"_text"] = arcade.Text(rot, x, y,
                                                    color=textcolor,
                                                    font_size=36,
                                                    font_name=constants.FONT_NAME,
                                                    anchor_x="center",
                                                    anchor_y="center")
        self.boss_script = danmaku.BossScriptPhase1(self, 640, 870)
        self.anim_coroutines = CoroutineSystem([self.anim_main()])
        self.game_running = False

    def draw(self):
        self.player_bullets.draw()
        self.bullets.draw()
        if self.focusing:
            arcade.draw_rectangle_filled(self.player.x, self.player.y,
                                         PLAYER_HITBOX_RADIUS * 2, PLAYER_HITBOX_RADIUS * 2,
                                         (255, 255, 255))
            arcade.draw_rectangle_outline(self.player.x, self.player.y,
                                         PLAYER_HITBOX_RADIUS * 2 - 2, PLAYER_HITBOX_RADIUS * 2 - 2,
                                         (255, 0, 0), border_width=2)

    def _draw(self):
        arcade.draw_rectangle_filled(self.player.x, self.player.y,
                                     PLAYER_HITBOX_RADIUS * 2, PLAYER_HITBOX_RADIUS * 2,
                                     (255, 0, 255))
        for bullet in self.bullets:
            if not bullet.intangible:
                arcade.draw_rectangle_outline(bullet.position[0], bullet.position[1],
                                              bullet.hitbox_radius_x * 2,
                                              bullet.hitbox_radius_y * 2, (255, 0, 0))
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

    def warning_fadein(self):
        for i in range(30):
            progress = i / 29
            self.gui["warning_background"].color = (0, 0, 0, int(128 * progress))
            self.gui["warning1"].color = (255, 0, 0, int(255 * progress))
            self.gui["warning2"].color = (255, 0, 0, int(255 * progress))
            yield

    def boss_title_type(self):
        for i in range(90):
            progress = i / 89
            type_len = 1 + int(progress * len(BOSS_TITLE))
            if type_len != len(self.gui["warning_title"].text):
                self.gui["warning_title"].text = BOSS_TITLE[:type_len]
            yield

    def warning_fadeout(self):
        for i in range(30):
            progress = i / 29
            self.gui["warning_background"].color = (0, 0, 0, int(128 * (1 - progress)))
            self.gui["warning1"].color = (200, 0, 0, int(255 * (1 - progress)))
            self.gui["warning2"].color = (255, 0, 0, int(255 * (1 - progress)))
            self.gui["warning_title"].color = (255, 255, 255, int(255 * (1 - progress)))
            yield

    def top_ui_fadein(self):
        for i in range(30):
            progress = i / 29
            self.gui["boss_title_background"].color = (0, 0, 0, int(128 * progress))
            self.gui["boss_title"].color = (255, 255, 255, int(255 * progress))
            self.gui["boss_health"].color = (255, 0, 0, int(255 * progress))
            self.gui["phase_marker"].color = (255, 255, 255, int(255 * progress))
            yield

    def warning_scroll(self):
        for i in range(180):
            self.gui["warning1"].x = 640 + (2*i)%(self.gui["warning1"].content_width/7)
            self.gui["warning2"].x = 640 - (2*i)%(self.gui["warning2"].content_width/7)
            yield

    def error_fadein(self):
        self.gui["error_message"] = arcade.Text(
                "ERROR: HEXAHEDRAL HELL", 640,
                1180 - 20, color=(255, 0, 0, 0), font_size=36,
                font_name=constants.FONT_NAME, anchor_x="center", anchor_y="center")
        for i in range(30):
            progress = 1 - (1-(i / 29))**2
            self.gui["boss_title_background"].b = 1180 - 40 * progress
            self.gui["error_message"].color = (255, 0, 0, int(255 * progress))
            yield

    def anim_main(self):
        self.anim_coroutines.add(self.warning_scroll())
        self.anim_coroutines.add(self.warning_fadein())
        yield from sleep_ticks(30)
        self.anim_coroutines.add(self.boss_title_type())
        yield from sleep_ticks(120)
        self.anim_coroutines.add(self.warning_fadeout())
        self.anim_coroutines.add(self.top_ui_fadein())
        yield from sleep_ticks(30)

    def tick(self, pressed_keys, newly_pressed_keys):
        self.focusing = arcade.key.LSHIFT in pressed_keys
        if not self.is_server and not self.boss.destructing:
            self.anim_coroutines.tick()
        if self.ticks == 180:
            self.game_running = True
        if self.boss_phase == 1 and self.boss_health <= self.boss_max_health / 2:
            self.boss_phase = 2
            self.despawn_all(self.bullets)
            self.boss_script = danmaku.BossScriptPhase2(self, 640, 870)
            if not self.is_server:
                self.anim_coroutines.add(self.error_fadein())
                for rot in 'DBL':
                    self.gui["rot_"+rot].color = (255, 0, 0, 64)
                    self.gui["rot_"+rot+"_text"].color = (255, 255, 255, 64)
        if self.game_running:
            if not self.boss.destructing:
                if not self.player.dead and arcade.key.SPACE in pressed_keys and self.ticks % 3 == 0:
                    self.player_shoot(danmaku.PlayerBullet(self, self.player.x - 18,
                                                           self.player.y + 20, 4000,
                                                           90))
                    self.player_shoot(danmaku.PlayerBullet(self, self.player.x + 18,
                                                           self.player.y + 20, 4000,
                                                           90))
                if self.boss_health > 0:
                    self.boss_script.tick()
                else:
                    self.boss.destruct()
                    self.despawn_all(self.bullets)
            if arcade.key.E in newly_pressed_keys and not self.player.dead:
                px = self.player.x
                py = self.player.y
                for rot in ROTATORS:
                    x,y = ROTATORS[rot]
                    l = x-ROTATOR_RADIUS
                    r = x+ROTATOR_RADIUS
                    t = y+ROTATOR_RADIUS
                    b = y-ROTATOR_RADIUS
                    if (px - PLAYER_HITBOX_RADIUS < r and
                        px + PLAYER_HITBOX_RADIUS > l and
                        py - PLAYER_HITBOX_RADIUS < t and
                        py + PLAYER_HITBOX_RADIUS > b and
                        (rot in 'UFR' or self.boss_phase == 2)):
                        self.boss_script.rotate(rot)
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
        if not self.player.dead:
            for bullet in self.bullets:
                if (not bullet.intangible and
                        px - PLAYER_HITBOX_RADIUS < bullet.position[
                            0] + bullet.hitbox_radius_x and
                        px + PLAYER_HITBOX_RADIUS > bullet.position[
                            0] - bullet.hitbox_radius_x and
                        py - PLAYER_HITBOX_RADIUS < bullet.position[
                            1] + bullet.hitbox_radius_y and
                        py + PLAYER_HITBOX_RADIUS > bullet.position[
                            1] - bullet.hitbox_radius_y):
                    self.player.decrease_health(bullet.damage)
                    if self.player.dead:
                        self.despawn_all(self.player_bullets)
                    else:
                        self.player.sprite.set_flashing(True)
                    if not bullet.permanent:
                        self.despawn(bullet)

        for bullet in self.player_bullets:
            if (not bullet.intangible and
                    self.boss_hitbox[0] < bullet.position[0] + bullet.hitbox_radius_x and
                    self.boss_hitbox[1] > bullet.position[0] - bullet.hitbox_radius_x and
                    self.boss_hitbox[2] < bullet.position[1] + bullet.hitbox_radius_y and
                    self.boss_hitbox[3] > bullet.position[1] - bullet.hitbox_radius_y):
                self.boss_health -= 1
                if self.boss_flash_cooldown == 0 and not self.boss.destructing:
                    self.boss_flash_cooldown = BOSS_FLASH_MAX_COOLDOWN
                    self.boss_flash_time = BOSS_FLASH_LEN
                    self.boss.sprite.set_animation("damage")
                self.despawn(bullet)

    def check_oob(self):
        for bullet in self.bullets:
            if bullet.permanent:
                continue
            x, y = bullet.position
            if x < 0 - MARGIN or x > 1280 + MARGIN or y < 0 - MARGIN or y > 1280 + MARGIN:
                self.destroy(bullet)
        for bullet in self.player_bullets:
            x, y = bullet.position
            if x < 0 - MARGIN or x > 1280 + MARGIN or y < 0 - MARGIN or y > 1280 + MARGIN:
                self.player_destroy(bullet)
        # i don't know how you clipped oob, but please don't do that
        if self.player.x <= 0 or self.player.x >= 1280 or self.player.y <= 0 or self.player.y >= 1280:
            self.player.decrease_health(500)
