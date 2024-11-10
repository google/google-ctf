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

# VERSION_NUMBER=1

import math
import random
from game import constants
from game.engine import hitbox
from game.components.boss.bullet import Bullet

class SimpleBullet(Bullet):
    def __init__(
            self,
            boss,
            x,
            y,
            speed,
            angle,
            damage=10,
    ):
        super().__init__(boss, x, y, speed, angle, damage)

    def run(self):
        yield from self.spawn_anim()
        while True:
            self.move_simple()
            yield


def addl_draw_info(b):
    return []

def fight(b):

    if b.state.rnd is None:
        b.state.rnd = random.Random(b.game.tics)
    b.state.slashbox_left = hitbox.Rectangle(b.x - 150, b.x, b.y - 100, b.y + 70)
    b.state.slashbox_right = hitbox.Rectangle(b.x, b.x + 150, b.y - 100, b.y + 70)

    # Slash at the player.
    b.state.slash_timer = max(0, b.state.slash_timer-1)
    if (not b.game.player.dead and b.state.slash_timer == 0
        and (b.state.name == "idle" or b.state.name == "jump")):
        offs = 150 if b.state.player_slashed else 120
        b.state.slashbox_left = hitbox.Rectangle(b.x - offs, b.x, b.y - 100, b.y + 70)
        b.state.slashbox_right = hitbox.Rectangle(b.x, b.x + offs, b.y - 100, b.y + 70)
        box = b.state.slashbox_left if b.sprite.flipped else b.state.slashbox_right
        if b.collides(b.game.player) or box.collides(b.game.player):
            b.sprite.set_animation("idle") # Reset animation
            b.state.player_slashed = False
            b.state.slash_timer = 60

    # Jump after the player.
    if (b.state.name == "idle" or b.state.name == "move") and b.state.slash_timer == 0:
        if (b.x1 - 100 < b.game.player.x2
            and b.x2 + 100 > b.game.player.x1
            and b.game.player.y1 > b.y2):
            b.state.name = "jump"
            b.state.timer = 60

    # Switch between states.
    b.state.timer = max(0, b.state.timer-1)
    if b.state.timer <= 0:
        b.place_at(b.x, b.orig_y) # Recover from jump
        if b.game.player.dead or b.state.slash_timer > 0:
            b.state.name = "idle"
        elif b.state.name == "teleport":
            b.state.name = "walk"
        elif abs(b.game.player.x - b.x) > 400:
            # Teleport near player
            b.state.name = "teleport"
        else:
            if len(b.state.next_states) == 0:
                b.state.next_states = ["idle", "walk", "shoot"] * 3
                b.state.rnd.shuffle(b.state.next_states)
            b.state.name = b.state.next_states.pop()
        match b.state.name:
            case "idle":
                b.state.timer = 60
            case "shoot":
                b.state.timer = 180
            case "walk":
                b.state.timer = 120
            case "teleport":
                b.state.timer = 90

    # State-specific logic.
    if ((b.state.slash_timer == 0 or b.state.slash_timer == 60)
        and (b.state.name != "jump" or b.state.timer >= 59)):
        b.sprite.set_flipped(b.game.player.x < b.x)
    match b.state.name:
        case "walk" | "jump":
            if b.sprite.flipped:
                if b.x1 > 0:
                    b.move(-3, 0)
            elif b.x2 < constants.SCREEN_WIDTH:
                b.move(3, 0)
            if b.state.name == "walk":
                if b.x1 - 60 < b.game.player.x2 and b.x2 + 60 > b.game.player.x1:
                    b.state.name = "idle"
                    b.state.timer = 0
            elif b.state.name == "jump":
                b.move(0, get_jump_offs(b.state.timer, 60))
        case "shoot":
            if b.state.timer % 30 == 0:
                shoot(b, SimpleBullet(b, b.x, b.y+20, 3.5, angle_to_player(b, b.x, b.y+40)))
        case "teleport":
            if b.state.timer == 45:
                d = 1 if b.game.player.sprite.flipped else -1
                pos = b.game.player.x + 99 * d
                alt = b.game.player.x - 99 * d
                if (pos < 50 and alt > pos) or (pos > constants.SCREEN_WIDTH - 50 and alt < pos):
                    pos = alt
                b.place_at(pos, b.y)

    if b.state.slash_timer > 0:
        if b.state.slash_timer <= 36:
            b.state.slashbox_left = hitbox.Rectangle(b.x - 130, b.x, b.y - 100, b.y - 30)
            b.state.slashbox_right = hitbox.Rectangle(b.x, b.x + 130, b.y - 100, b.y - 30)
        else:
            b.state.slashbox_left = hitbox.Rectangle(b.x - 150, b.x, b.y - 100, b.y + 70)
            b.state.slashbox_right = hitbox.Rectangle(b.x, b.x + 150, b.y - 100, b.y + 70)
        box = b.state.slashbox_left if b.sprite.flipped else b.state.slashbox_right
        if (b.state.slash_timer < 52 and not b.state.player_slashed
            and (b.collides(b.game.player) or box.collides(b.game.player))):
            b.state.player_slashed = True
            b.game.player.decrease_health(20, "fighting_boss")
            b.game.player.sprite.set_flashing(True)

    update_animation(b)

def angle_to_player(b, x, y):
    return math.degrees(math.atan2(b.game.player.y - y, b.game.player.x - x))

def shoot(b, bullet):
    if not b.destructing:
        b.bullets_to_add.append(bullet)

def get_jump_offs(timer, max_val):
    return 10 * (timer *  2 - max_val) / max_val

def update_animation(b):
    if b.state.slash_timer > 0:
        b.sprite.set_animation("slash")
    elif b.state.name == "shoot":
        b.sprite.set_animation("idle")
    elif b.state.name == "teleport":
        if b.state.timer > 60:
            b.sprite.set_animation("disappear")
        elif b.state.timer > 30:
            b.sprite.set_animation("idle")
        else:
            b.sprite.set_animation("appear")
    else:
        b.sprite.set_animation(b.state.name)
