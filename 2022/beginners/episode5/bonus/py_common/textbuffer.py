#!/usr/bin/env python3
# Copyright 2022 Google LLC
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
import socket
import threading
import time
from datetime import datetime
from filters import badlang_filter_load, badlang_filter_check

class TextBuffer:
  W = 36
  H = 14

  def __init__(self, udp_port):
    self.udp_port = udp_port

    self.buffer = bytearray(TextBuffer.W * TextBuffer.H)

    self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    self.cursor = [0, 0]  # X, Y
    self.iter = 0

    self.attr = 0
    self.show_cursor = True
    self.show_alive = False
    self.add_alive = False

    self.badlang_checks_enabled = False

    self.updater_th = threading.Thread(target=self.updater, daemon=True)
    self.updater_th.start()

  def updater(self):
    last_iter = -1

    last_show_alive = time.time()
    last_show_alive_state = self.show_alive

    while True:
      if self.show_alive:
        last_show_alive_state = True

        now = time.time()
        if now - last_show_alive > 1.0:  # Seconds.
          last_show_alive = now
          self.add_alive = not self.add_alive
          self.iter += 1

      elif last_show_alive_state:
        last_show_alive_state = False
        self.add_alive = False
        self.iter += 1

      if last_iter == self.iter:
        time.sleep(0.034)  # No sense in sending stuff faster than 30 FPS.
        continue

      last_iter = self.iter

      if self.badlang_checks_enabled:
        self.do_badlang_checks()  # This might totally clear the frame.

      self.send_buffer()

  def enforce_badlang_filter(self, screen):
    print("warning: bad lang filter clearing screen:")
    for i in range(TextBuffer.H):
      print("%.2x: %s" % (i, screen[i*TextBuffer.W:(i+1)*TextBuffer.W]))
    self.clear()

  def do_badlang_checks(self):
    buffer = self.buffer[:]
    for i in range(TextBuffer.W * TextBuffer.H):
      buffer[i] &= 0x7f

    txt = buffer.decode().replace("\0", " ")
    if not badlang_filter_check(txt):
      self.enforce_badlang_filter(txt)
      return

    # Check vertically as well.
    transp_txt = bytearray(TextBuffer.W * TextBuffer.H)
    for i in range(TextBuffer.W):
      for j in range(TextBuffer.H):
        transp_txt[i * TextBuffer.H + j] = buffer[i + j * TextBuffer.W]
    v_txt = transp_txt.decode().replace("\0", " ")
    if not badlang_filter_check(v_txt):
      self.enforce_badlang_filter(txt)
      return

  # If attr is set, charts are printed in negative.
  def set_attr(self, attr):
    if attr:
      self.attr = 0x80
    else:
      self.attr = 0x00

  def set_cursor_visibility(self, show):
    self.show_cursor = show
    self.iter += 1

  def set_show_alive(self, show):
    # Blinks a dot in bottom-right corner every second.
    self.show_alive = show

  def send_custom(self, opcode, payload):
    packet = bytearray(1 + len(payload))
    packet[0] = opcode
    packet[1:] = payload

    self.s.sendto(packet, ("127.0.0.1", self.udp_port))

  def send_buffer(self):
    packet = bytearray(1 + TextBuffer.W * TextBuffer.H)
    packet[0] = 0x00  # TextBuffer opcode.
    packet[1:] = self.buffer

    if self.show_cursor:
      idx = self.cursor[0] + self.cursor[1] * TextBuffer.W
      packet[1 + idx] ^= 0x80

    if self.add_alive:
      idx = TextBuffer.W * TextBuffer.H - 1
      packet[1 + idx] = (packet[1 + idx] & 0x80) | ord('.')

    self.s.sendto(packet, ("127.0.0.1", self.udp_port))

  def scroll_up(self):
    self.buffer[:TextBuffer.W * (TextBuffer.H - 1)] = (
        self.buffer[TextBuffer.W:])
    self.buffer[TextBuffer.W * (TextBuffer.H - 1):] = (
        bytearray(TextBuffer.W))
    self.cursor[0] = 0
    self.cursor[1] = TextBuffer.H - 1
    self.iter += 1

  def print(self, s):
    for ch in s:
      self.__putchar_worker(ch)
    self.iter += 1

  def __putchar_newline(self):
    self.cursor[0] = 0
    self.cursor[1] += 1
    if self.cursor[1] >= TextBuffer.H:
      self.scroll_up()

  def __putchar_worker(self, ch):
    if ch == '\n':
      self.__putchar_newline()
      return

    if ch == '\r':
      self.cursor[0] = 0
      return

    idx = self.cursor[0] + self.cursor[1] * TextBuffer.W
    self.buffer[idx] = ord(ch) | self.attr

    self.cursor[0] += 1
    if self.cursor[0] >= TextBuffer.W:
      self.cursor[0] = 0
      self.cursor[1] += 1
      if self.cursor[1] >= TextBuffer.H:
        self.scroll_up()

  def gotoxy(self, x, y):
    if x >= TextBuffer.W:
      x = TextBuffer.W - 1

    if y >= TextBuffer.H:
      y = TextBuffer.H - 1

    self.cursor[0] = x
    self.cursor[1] = y
    self.iter += 1

  def printxy(self, x, y, s):
    # This one does move the cursor.
    self.gotoxy(x, y)
    self.print(s)

  def putchar_xy(self, x, y, ch):
    # Puts char without moving the cursor.
    if x >= TextBuffer.W:
      x = TextBuffer.W - 1

    if y >= TextBuffer.H:
      y = TextBuffer.H - 1

    idx = x + y * TextBuffer.W
    self.buffer[idx] = ord(ch) | self.attr
    self.iter += 1

  def getchar_xy(self, x, y):
    idx = x + y * TextBuffer.W
    return chr((self.buffer[idx] & 0x7f))

  def clear(self):
    clear_char = b'\x80' if self.attr else b'\0'
    self.buffer[:] = clear_char * (TextBuffer.W * TextBuffer.H)
    self.cursor[0] = 0
    self.cursor[1] = 0
    self.iter += 1

  def clear_line(self, y):
    # Does NOT move the cursor.
    self.fill_line(y, b'\x80' if self.attr else b'\0')

  def fill_line(self, y, ch):
    # Does NOT move the cursor.
    clear_char = bytes([ord(ch)])
    line_idx = TextBuffer.W * y
    self.buffer[line_idx:line_idx + TextBuffer.W] = clear_char * TextBuffer.W
    self.iter += 1

  def print_center(self, y, s):
    x = (TextBuffer.W - len(s)) // 2
    if x < 0:
      x = 0
    self.gotoxy(x, y)
    self.print(s)
    # iter increment done by print

badlang_filter_load()

if __name__ == "__main__":
  txt1 = TextBuffer(23400)
  txt2 = TextBuffer(23401)

  txt1.set_cursor_visibility(False)
  txt1.set_attr(True)
  txt1.print_center(1, " Clock ")
  txt1.set_attr(False)
  txt1.print_center(2, "^^^^^^^")

  txt2.print("Basic print test\nNew Line\nAAAAAAAA\rBBBB\nCursor:")
  txt2.set_show_alive(True)

  txt2.putchar_xy(TextBuffer.W - 1, TextBuffer.H - 1, '#')

  dot = True
  while True:
    time.sleep(1)
    if dot:
      t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else:
      t = datetime.now().strftime("%Y-%m-%d %H %M %S")
    dot = not dot
    txt1.print_center(3, t)


