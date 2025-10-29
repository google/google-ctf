# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array
import collections
import gzip
import math
import struct

import arcade

WINDOW_WIDTH = 1200
WINDOW_HEIGHT = 900
TILESIZE = 30

assert WINDOW_WIDTH % TILESIZE == 0
assert WINDOW_HEIGHT % TILESIZE == 0

print('loading shakashaka puzzle...')
with gzip.open('puzzlepuzzle.dat.gz', 'rb') as f:
  data = f.read()
print('loaded!')

width = struct.unpack('<I', data[:4])[0]
height = struct.unpack('<I', data[4:8])[0]
data = array.array('B', data)

arcade.resources.load_kenney_fonts()
arcade.resources.load_liberation_fonts()


def get_tile(r, c):
  if not (0 <= r < height and 0 <= c < width):
    return 0
  idx = r * width + c
  x = data[8 + idx // 2]
  if idx % 2 == 0:
    return x >> 4
  else:
    return x & 0xF


def set_tile(r, c, val):
  if not (0 <= r < height and 0 <= c < width):
    return
  idx = r * width + c
  x = data[8 + idx // 2]
  if idx % 2 == 0:
    x = (x & 0xF) | (val << 4)
  else:
    x = (x & 0xF0) | val
  data[8 + idx // 2] = x


class ShakashakaViewer(arcade.View):

  def __init__(self):
    super().__init__()
    self.window.set_vsync(True)
    self.background_color = arcade.color.BLACK
    self.cur_r = 0
    self.cur_c = 8424
    self.t = 0
    self.controls_text = arcade.Text(
        'WASD/arrow keys: move\nClick: input solution\nEnter: check solution',
        10,
        WINDOW_HEIGHT - 10,
        arcade.color.GREEN,
        20,
        anchor_y='top',
        width=400,
        multiline=True,
        font_name='Kenney Future Narrow',
    )
    self.wrong_text = arcade.Text(
        'wrong...',
        WINDOW_WIDTH / 2,
        WINDOW_HEIGHT / 2,
        arcade.color.RED.replace(a=0),
        100,
        anchor_x='center',
        anchor_y='center',
        font_name='Kenney Future',
    )
    self.correct_texts = []
    widths = []
    for i, c in enumerate('correct!'):
      t = arcade.Text(
          c,
          WINDOW_WIDTH / 2,
          WINDOW_HEIGHT / 2 + 100,
          arcade.color.GREEN.replace(a=0),
          100,
          anchor_x='center',
          anchor_y='center',
          font_name='Kenney Future',
      )
      widths.append(25 if c == '!' else t.content_width)  # kerning...
      self.correct_texts.append(t)
    cur_x = WINDOW_WIDTH / 2 - (sum(widths) - (widths[0] + widths[1]) / 2) / 2
    for i, t in enumerate(self.correct_texts):
      t.x = cur_x
      if i < len(widths) - 1:
        cur_x += (widths[i] + widths[i + 1]) / 2
    self.flag_text = arcade.Text(
        '',
        WINDOW_WIDTH / 2,
        WINDOW_HEIGHT / 2 - 100,
        arcade.color.GREEN,
        14,
        anchor_x='center',
        anchor_y='center',
        font_name='Liberation Mono',
    )

  def on_update(self, delta_time):
    self.t += delta_time
    self.wrong_text.rotation = math.sin(4 * self.t) * 15
    self.wrong_text.color = self.wrong_text.color.replace(
        a=max(0, self.wrong_text.color.a - 2)
    )
    for i, t in enumerate(self.correct_texts):
      t.y = WINDOW_HEIGHT / 2 + 100 + math.sin(4 * self.t - i) * 30

  def on_draw(self):
    self.clear()
    for r in range(WINDOW_HEIGHT // TILESIZE):
      for c in range(WINDOW_WIDTH // TILESIZE):
        cx = (c + 0.5) * TILESIZE
        cy = WINDOW_HEIGHT - (r + 0.5) * TILESIZE
        match get_tile(r + self.cur_r, c + self.cur_c):
          case 0:
            pass
          case 1:
            arcade.draw_circle_outline(
                cx, cy, TILESIZE * 0.35, arcade.color.RED, 5
            )
          case 2:
            arcade.draw_point(cx, cy, arcade.color.YELLOW, 10)
          case 3:
            arcade.draw_point(cx - 8, cy, arcade.color.GREEN, 10)
            arcade.draw_point(cx + 8, cy, arcade.color.GREEN, 10)
          case 4:
            arcade.draw_point(cx - 8, cy - 8, arcade.color.BLUE, 10)
            arcade.draw_point(cx + 8, cy - 8, arcade.color.BLUE, 10)
            arcade.draw_point(cx, cy + 8, arcade.color.BLUE, 10)
          case 15:
            arcade.draw_point(cx - 8, cy - 8, arcade.color.PURPLE, 10)
            arcade.draw_point(cx + 8, cy - 8, arcade.color.PURPLE, 10)
            arcade.draw_point(cx - 8, cy + 8, arcade.color.PURPLE, 10)
            arcade.draw_point(cx + 8, cy + 8, arcade.color.PURPLE, 10)
          case 5 | 10:
            arcade.draw_point(cx, cy, arcade.color.WHITE, TILESIZE)
          case 6 | 11:
            arcade.draw_polygon_filled(
                [
                    (cx - TILESIZE / 2, cy - TILESIZE / 2),
                    (cx + TILESIZE / 2, cy - TILESIZE / 2),
                    (cx + TILESIZE / 2, cy + TILESIZE / 2),
                ],
                arcade.color.WHITE,
            )
          case 7 | 12:
            arcade.draw_polygon_filled(
                [
                    (cx - TILESIZE / 2, cy - TILESIZE / 2),
                    (cx + TILESIZE / 2, cy - TILESIZE / 2),
                    (cx - TILESIZE / 2, cy + TILESIZE / 2),
                ],
                arcade.color.WHITE,
            )
          case 8 | 13:
            arcade.draw_polygon_filled(
                [
                    (cx - TILESIZE / 2, cy + TILESIZE / 2),
                    (cx + TILESIZE / 2, cy + TILESIZE / 2),
                    (cx + TILESIZE / 2, cy - TILESIZE / 2),
                ],
                arcade.color.WHITE,
            )
          case 9 | 14:
            arcade.draw_polygon_filled(
                [
                    (cx - TILESIZE / 2, cy + TILESIZE / 2),
                    (cx + TILESIZE / 2, cy + TILESIZE / 2),
                    (cx - TILESIZE / 2, cy - TILESIZE / 2),
                ],
                arcade.color.WHITE,
            )

    for r in range(WINDOW_HEIGHT // TILESIZE):
      arcade.draw_line(
          0, r * TILESIZE, WINDOW_WIDTH, r * TILESIZE, arcade.color.GRAY, 1
      )
    for c in range(WINDOW_WIDTH // TILESIZE):
      arcade.draw_line(
          c * TILESIZE, 0, c * TILESIZE, WINDOW_HEIGHT, arcade.color.GRAY, 1
      )

    self.controls_text.draw()
    self.wrong_text.draw()
    for text in self.correct_texts:
      text.draw()
    self.flag_text.draw()

  def on_mouse_press(self, x, y, button, key_modifiers):
    r = self.cur_r + int((WINDOW_HEIGHT - y) / TILESIZE)
    c = self.cur_c + int(x / TILESIZE)
    tile = get_tile(r, c)
    if not 5 <= tile <= 14:
      return
    base = 5 if 5 <= tile <= 9 else 10
    xq = int(x / (TILESIZE / 2)) % 2
    yq = int(y / (TILESIZE / 2)) % 2
    match xq, yq:
      case (0, 0):
        new_tile = base + 3
      case (0, 1):
        new_tile = base + 1
      case (1, 0):
        new_tile = base + 4
      case (1, 1):
        new_tile = base + 2
    if tile == new_tile:
      new_tile = base
    set_tile(r, c, new_tile)

  def on_key_press(self, key, modifiers):
    if key in [arcade.key.UP, arcade.key.W]:
      self.cur_r -= 1
    elif key in [arcade.key.DOWN, arcade.key.S]:
      self.cur_r += 1
    elif key in [arcade.key.LEFT, arcade.key.A]:
      self.cur_c -= 1
    elif key in [arcade.key.RIGHT, arcade.key.D]:
      self.cur_c += 1
    elif key == arcade.key.ENTER:
      if self.check_solution():
        for text in self.correct_texts:
          text.color = arcade.color.GREEN
        flag_bits = ''
        for r in range(height):
          for c in range(width):
            tile = get_tile(r, c)
            if 10 <= tile <= 14:
              flag_bits += str(int(11 <= tile <= 14))
          if len(flag_bits) > 0:
            break
        flag = ''
        for i in range(0, len(flag_bits), 8):
          flag += chr(int(flag_bits[i : i + 8], 2))
        self.flag_text.text = 'CTF{' + flag + '}'
      else:
        self.wrong_text.color = self.wrong_text.color.replace(a=255)

  def check_solution(self):
    visited = array.array('B', bytes(math.ceil(width * height / 8)))

    def get_visited(r, c):
      if not (0 <= r < height and 0 <= c < width):
        return 1
      idx = r * width + c
      return (visited[idx // 8] >> (idx % 8)) & 1

    def set_visited(r, c):
      if not (0 <= r < height and 0 <= c < width):
        return
      idx = r * width + c
      visited[idx // 8] = (visited[idx // 8] & (~(1 << (idx % 8)))) | (
          1 << (idx % 8)
      )

    for cur_r in range(height):
      for cur_c in range(width):
        if get_visited(cur_r, cur_c):
          continue
        tile = get_tile(cur_r, cur_c)
        if not 5 <= tile <= 14:
          set_visited(cur_r, cur_c)
          if tile not in {1, 2, 3, 4, 15}:
            continue
          filled = 0
          for r, c in [
              (cur_r + 1, cur_c),
              (cur_r - 1, cur_c),
              (cur_r, cur_c + 1),
              (cur_r, cur_c - 1),
          ]:
            t = get_tile(r, c)
            if 6 <= t <= 9 or 11 <= t <= 14:
              filled += 1
          match tile:
            case 1:
              if filled != 0:
                return False
            case 2:
              if filled != 1:
                return False
            case 3:
              if filled != 2:
                return False
            case 4:
              if filled != 3:
                return False
            case 15:
              if filled != 4:
                return False
          continue
        squ = 0
        tri = 0
        tl = (cur_r, cur_c)
        rmin = cur_r
        rmax = cur_r
        cmin = cur_c
        cmax = cur_c
        component = set()
        q = collections.deque([(cur_r, cur_c)])
        while len(q) > 0:
          r, c = q.popleft()
          set_visited(r, c)
          component.add((r, c))
          tl = min(tl, (r, c))
          rmin = min(rmin, r)
          rmax = max(rmax, r)
          cmin = min(cmin, c)
          cmax = max(cmax, c)
          tile = get_tile(r, c)
          match tile:
            case 5 | 10:
              squ += 1
              if (
                  not get_visited(r + 1, c)
                  and get_tile(r + 1, c) in {5, 10, 8, 13, 9, 14}
                  and (r + 1, c) not in q
              ):
                q.append((r + 1, c))
              if (
                  not get_visited(r, c + 1)
                  and get_tile(r, c + 1) in {5, 10, 7, 12, 9, 14}
                  and (r, c + 1) not in q
              ):
                q.append((r, c + 1))
              if (
                  not get_visited(r - 1, c)
                  and get_tile(r - 1, c) in {5, 10, 6, 11, 7, 12}
                  and (r - 1, c) not in q
              ):
                q.append((r - 1, c))
              if (
                  not get_visited(r, c - 1)
                  and get_tile(r, c - 1) in {5, 10, 6, 11, 8, 13}
                  and (r, c - 1) not in q
              ):
                q.append((r, c - 1))
            case 6 | 11:
              tri += 1
              if (
                  not get_visited(r + 1, c)
                  and get_tile(r + 1, c) in {5, 10, 8, 13, 9, 14}
                  and (r + 1, c) not in q
              ):
                q.append((r + 1, c))
              if (
                  not get_visited(r, c + 1)
                  and get_tile(r, c + 1) in {5, 10, 7, 12, 9, 14}
                  and (r, c + 1) not in q
              ):
                q.append((r, c + 1))
            case 7 | 12:
              tri += 1
              if (
                  not get_visited(r + 1, c)
                  and get_tile(r + 1, c) in {5, 10, 8, 13, 9, 14}
                  and (r + 1, c) not in q
              ):
                q.append((r + 1, c))
              if (
                  not get_visited(r, c - 1)
                  and get_tile(r, c - 1) in {5, 10, 6, 11, 8, 13}
                  and (r, c - 1) not in q
              ):
                q.append((r, c - 1))
            case 8 | 13:
              tri += 1
              if (
                  not get_visited(r - 1, c)
                  and get_tile(r - 1, c) in {5, 10, 6, 11, 7, 12}
                  and (r - 1, c) not in q
              ):
                q.append((r - 1, c))
              if (
                  not get_visited(r, c + 1)
                  and get_tile(r, c + 1) in {5, 10, 7, 12, 9, 14}
                  and (r, c + 1) not in q
              ):
                q.append((r, c + 1))
            case 9 | 14:
              tri += 1
              if (
                  not get_visited(r - 1, c)
                  and get_tile(r - 1, c) in {5, 10, 6, 11, 7, 12}
                  and (r - 1, c) not in q
              ):
                q.append((r - 1, c))
              if (
                  not get_visited(r, c - 1)
                  and get_tile(r, c - 1) in {5, 10, 6, 11, 8, 13}
                  and (r, c - 1) not in q
              ):
                q.append((r, c - 1))
        if tri % 2 == 1:
          return False
        a = squ + tri // 2
        if tri == 0:
          if a != (rmax - rmin + 1) * (cmax - cmin + 1):
            return False
        else:
          r = tl[0]
          c = tl[1] + 1
          if get_tile(r, c) not in {7, 12} or (r, c) not in component:
            return False
          w = 1
          while (
              get_tile(r + 1, c + 1) in {7, 12} and (r + 1, c + 1) in component
          ):
            w += 1
            r += 1
            c += 1
          r += 1
          if get_tile(r, c) not in {9, 14} or (r, c) not in component:
            return False
          h = 1
          while (
              get_tile(r + 1, c - 1) in {9, 14} and (r + 1, c - 1) in component
          ):
            h += 1
            r += 1
            c -= 1
          c -= 1
          for _ in range(w):
            if get_tile(r, c) not in {8, 13} or (r, c) not in component:
              return False
            r -= 1
            c -= 1
          c += 1
          for _ in range(h):
            if get_tile(r, c) not in {6, 11} or (r, c) not in component:
              return False
            r -= 1
            c += 1
          if a != w * h * 2:
            return False
    return True


try:
  window = arcade.Window(WINDOW_WIDTH, WINDOW_HEIGHT, 'puzzlepuzzle')
  game = ShakashakaViewer()
  window.show_view(game)
  arcade.run()
except KeyboardInterrupt:
  pass
except Exception as e:
  print("couldn't run arcade!")
  print(e)
