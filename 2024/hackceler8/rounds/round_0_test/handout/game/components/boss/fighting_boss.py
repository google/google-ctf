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
import math
from collections import deque
from game import constants
from game.components.boss.boss import Boss
from game.components.boss.bullet import Bullet
from game.engine import gfx
from game.engine import hitbox

import game.components.boss.implementation

MARGIN = 50
BOSS_TITLE = 'villAIn Mk.II "Test Round Boss"'
MAX_HEALTH = 500
HEALTHBAR_LEN = 1240


class Gui:
    layer = None
    title_bg_alpha = 0
    boss_title_alpha = 0
    boss_health_alpha = 0
    warning_bg_alpha = 0
    warning_hue = 1
    warning_alpha = 0
    warning_title_text = ""
    warning_title_alpha = 1

class State:
    name = "idle"
    timer = 60
    slash_timer = 0
    next_states = []
    rnd =  None
    slashbox_left = None
    slashbox_right = None
    player_slashed = False

class FightingBoss(Boss):
    def __init__(self, coords):
        super().__init__(coords, name="fighting_boss", tileset_path="resources/villain/fuego.h8t")
        self.name = "fighting_boss"
        self.set_health(MAX_HEALTH)
        self.ticks = 0
        self.bullets: list[Bullet] = []
        self.bullets_to_add = deque()
        self.bullets_to_remove = deque()
        self.gui = Gui()
        self.does_respawn = False
        self.state = State()
        rect = hitbox.Rectangle(coords.x - 40, coords.x + 40, coords.y - 90, coords.y + 50)
        self.update_hitbox(rect)


    def get_draw_info(self):
        info = [
            (i.get_draw_info() for i in self.bullets),
        ]
        info += game.components.boss.implementation.addl_draw_info(self)
        if self.state.name == "teleport" and self.state.timer > 30 and self.state.timer <= 60:
            return info
        return [super().get_draw_info()] + info

    def _chat(self):
        self.game.display_textbox("¡LESS TALKING MORE FIGHTING MI AMIGA!")

    def reload_module(self):
        if self.game.is_server:
            self.game.server_send_reload_module(['game.components.boss.implementation'])
        else:
            self.game.client_start_waiting_reload_module()

    def draw_gui(self):
        super().draw_gui()

        if not self.gui.layer:
            self.gui.layer = gfx.ShapeLayer()
        self.gui.layer.clear()

        self.gui.layer.add(gfx.lrtb_rectangle_filled(
            0, constants.SCREEN_WIDTH, constants.SCREEN_HEIGHT, 660,
            (0, 0, 0, int(255 * self.gui.title_bg_alpha))
        ))
        boss_health_percent = max(0, self.health / MAX_HEALTH)
        if boss_health_percent > 0:
            self.gui.layer.add(gfx.lrtb_rectangle_filled(
                640 - HEALTHBAR_LEN // 2,
                640 - HEALTHBAR_LEN // 2 + boss_health_percent * HEALTHBAR_LEN,
                700, 680,
                color=(255, 0, 0, int(255 * self.gui.boss_health_alpha))
            ))
        gfx.draw_txt("boss_title", gfx.FONT_PIXEL[40], BOSS_TITLE,
                     640, 1240, color=(1, 1, 1, self.gui.boss_title_alpha))
        self.gui.layer.add(gfx.lrtb_rectangle_filled(
            0, constants.SCREEN_WIDTH, 510, 164,
            (0, 0, 0, int(255 * self.gui.warning_bg_alpha)),
        ))
        gfx.draw_txt("warning", gfx.FONT_PIXEL[120], "WARNING",
                     250, 320, color=(self.gui.warning_hue, 0, 0, self.gui.warning_alpha))
        gfx.draw_txt("warning_title", gfx.FONT_PIXEL[40], self.gui.warning_title_text,
                     100, 50 - 3, color=(1, 1, 1, self.gui.warning_title_alpha))

        self.gui.layer.build()
        self.gui.layer.draw()

    def tick(self):
        super().tick()

        if self.ticks < 270 and not self.destructing:
            self.game.player.immobilized = True
            self.startup_sequence()
            self.ticks += 1
            return
        if self.ticks == 270:
            self.game.player.immobilized = False

        if not self.destructing and self.health > 0:
            self.fight()

        for bullet in self.bullets:
            next(bullet.updater)
        self.check_collisions()
        self.check_oob()
        while len(self.bullets_to_add) > 0:
            self.bullets.append(self.bullets_to_add.pop())
        while len(self.bullets_to_remove) > 0:
            self.bullets.remove(self.bullets_to_remove.pop())
        self.ticks += 1

    def startup_sequence(self):
        self.sprite.set_flipped(self.game.player.x < self.x)
        if self.ticks < 30:
            progress = self.ticks / 29
            self.gui.warning_bg_alpha = progress * 0.5
            self.gui.warning_alpha = progress
        elif self.ticks < 210:
            self.sprite.set_animation("point")
            progress = (self.ticks - 30) / 179
            type_len = 1 + int(progress * len(BOSS_TITLE))
            if type_len != len(self.gui.warning_title_text):
                self.gui.warning_title_text = BOSS_TITLE[:type_len]

            hue_prog = ((self.ticks - 30) % 60) / 59
            if hue_prog < 0.5:
                self.gui.warning_hue = 1 - hue_prog
            else:
                self.gui.warning_hue = hue_prog
        elif self.ticks >= 240:
            self.sprite.set_animation("idle")
            progress = (self.ticks - 240) / 29
            self.gui.warning_bg_alpha = 0.5 * (1 - progress)
            self.gui.warning_alpha = 1 - progress
            self.gui.warning_title_alpha = 1 - progress,
            try:
                self.gui.warning_title_alpha = self.gui.warning_title_alpha[0]
            except:
                pass
            title_bg_alpha = int(128 * progress)
            self.gui.boss_title_alpha = progress
            self.gui.boss_health_alpha = progress

    def fight(self):
        return game.components.boss.implementation.fight(self)

    def reset(self):
        super().reset()
        self.set_health(MAX_HEALTH)
        self.bullets = []
        self.state = State()
        self.sprite.set_animation("idle")
        self.sprite.set_flipped(False)

    def decrease_health(self, points, source=None):
        if self.state.name == "teleport":
            return False
        self.health = max(0, self.health - points * 10)
        return True

    def check_death(self):
        if self.health <= 0 and not self.destructing:
            self.destruct()
            self.despawn_all(self.bullets)

    @staticmethod
    def despawn(bullet):
        bullet.updater = bullet.despawn_anim()

    @staticmethod
    def despawn_all(bullets):
        for bullet in bullets:
            bullet.updater = bullet.despawn_anim()

    def destroy_bullet(self, bullet):
        self.bullets_to_remove.append(bullet)

    def check_collisions(self):
        px = self.game.player.x
        py = self.game.player.y
        for bullet in self.bullets:
            if bullet.intangible:
                continue
            r = hitbox.Rectangle(
                bullet.x - bullet.hitbox_w * 0.5, bullet.x + bullet.hitbox_w * 0.5,
                bullet.y - bullet.hitbox_w * 0.5, bullet.y + bullet.hitbox_w * 0.5)
            if r.collides(self.game.player):
                self.game.player.decrease_health(bullet.damage, "fighting_boss")
                if not self.game.player.dead:
                    self.game.player.sprite.set_flashing(True)
                self.despawn(bullet)

    def check_oob(self):
        for bullet in self.bullets:
            if (
                    bullet.x < 0 - MARGIN
                    or bullet.x > constants.SCREEN_WIDTH + MARGIN
                    or bullet.y < 0 - MARGIN
                    or bullet.y > constants.SCREEN_HEIGHT + MARGIN
            ):
                self.destroy_bullet(bullet)
        # I don't know how you clipped oob, but please don't do that
        if (
                self.game.player.x <= 0
                or self.game.player.x >= constants.SCREEN_WIDTH
                or self.game.player.y <= 0
                or self.game.player.y >= constants.SCREEN_HEIGHT
        ):
            self.game.player.decrease_health(200, "fighting_boss")
