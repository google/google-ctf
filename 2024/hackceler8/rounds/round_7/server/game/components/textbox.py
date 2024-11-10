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
from __future__ import annotations

import logging
import imgui
from math import floor
from typing import Optional, TYPE_CHECKING, Any
import moderngl_window as mglw

from game import venator
from game import constants
from game.engine import gfx
from game.engine.keys import Keys

if TYPE_CHECKING:
    from game.venator import Venator


TEXT_X = 33 # from left edge of bg


class TextObj:
    def __init__(self, text: str, headless: bool = False, x: int = 0, y: int = 0, col: gfx.Color = None, font: int = 0,
                 allow_input: bool = False, observer_hack: bool = False):
        self.text = text
        self.headless = headless
        self.x = x
        self.y = y
        self.col = col
        self.font = font
        self.allow_input = allow_input
        self.observer_hack = observer_hack
        self.left_padding = TEXT_X
        self.top_padding = 30

    def draw(self):
        scale = gfx.GLOBAL_WINDOW.scale
        with imgui.font(self.font):
            imgui.push_style_color(imgui.COLOR_TEXT, *self.col)
            imgui.set_cursor_pos(imgui.Vec2(scale*(self.x+self.left_padding), scale*(self.y + self.top_padding)))
            if self.allow_input:
                imgui.push_item_width(750 * scale)
                imgui.push_style_color(imgui.COLOR_FRAME_BACKGROUND, 0, 0.5, 0)
                imgui.push_style_color(imgui.COLOR_BORDER, *self.col)
                imgui.push_style_var(imgui.STYLE_FRAME_BORDERSIZE, 2)
                imgui.set_keyboard_focus_here()
                if self.observer_hack:
                    _, _ = imgui.input_text("", self.text, flags=imgui.INPUT_TEXT_READ_ONLY)
                else:
                    _, self.text = imgui.input_text("", self.text)
                imgui.pop_style_var()
                imgui.pop_style_color()
                imgui.pop_style_color()
                imgui.pop_item_width()
            else:
                imgui.text_colored(self.text, *self.col)
            imgui.pop_style_color()  # COLOR_TEXT


class Textbox:
    CHARS_PER_SECOND = 20
    TEXT_COLOR = (164 / 255, 198 / 255, 57 / 255, 1)
    TEXT_SIZE = 30
    LINE_DISTANCE = 40
    LINE_MAX_CHARS = 30
    MAX_LINES = 5

    def __init__(
            self,
            game: Venator,
            text: str,
            done_fun,
            choices=None,
            free_text=False,
            process_fun=None,
            from_server=False,
            response_callbacks=None
    ):
        if choices is None:
            choices = []

        if response_callbacks is None:
            response_callbacks = {}

        self.bg = gfx.GuiImage.load(gfx.GLOBAL_WINDOW, "resources/textbox/bg.png")
        self.more_arrow = gfx.GuiImage.load(gfx.GLOBAL_WINDOW, "resources/textbox/more-arrow.png")
        self.choice_arrow = gfx.GuiImage.load(gfx.GLOBAL_WINDOW, "resources/textbox/choice-arrow.png")
        self.BG_X = constants.SCREEN_WIDTH/2 - self.bg.width/2
        self.BG_Y = constants.SCREEN_HEIGHT - self.bg.height - 50
        self.TEXT_Y = self.bg.height - 40

        self.game = game
        self.done_fun = done_fun
        self.free_text = free_text
        self.process_fun = process_fun
        self.choices = choices
        self.from_server = from_server
        self.response_callbacks = response_callbacks

        self.selection = 0
        if free_text and len(choices) > 0:
            logging.error("Both free text and multiple choice specified")
        if self.game.is_server and from_server:
            logging.error("Using from_server when in server mode already")

        self.text: Optional[str] = None
        self.lines: list[str] = []
        self.remaining_lines: list[str] = []
        self.choice_objs = []
        self.text_input: Optional[TextObj] = None
        self.ui_manager = None

        self.text_input_appeared = False
        self.t = 0
        self.done_scrolling = False
        self.more_arrow_time = 0
        if from_server:
            # Wait for the server's text.
            self.text_objs = None
        else:
            self.init_text(text, choices, free_text)
        if not from_server:
            logging.info(f'Chat: "{text}"')

    def init_text(self, text: str, choices, free_text):
        self.text = text
        self.lines = self.get_lines(text, choices, free_text)
        self.remaining_lines = self.lines[self.MAX_LINES:]
        self.lines = self.lines[: self.MAX_LINES]
        self.text_objs = self.get_text_objs(self.lines)
        self.choice_objs = self.get_choice_objs(self.choices)
        self.text_input = self.get_free_input_obj()
        if len(self.choices) > 0:
            self.text_input.text = self.choices[self.selection]

    def get_lines(self, text: str, choices, free_text) -> list[str]:
        initial_lines = text.strip().split("\n")
        lines = []
        for l in initial_lines:
            lines += self.split_line_if_too_long(l)
        n = 1 if free_text else len(choices)
        return self.make_space_for_input(lines, n)

    def make_space_for_input(self, lines, n):
        # Only MAX_LINES-1 choices displayed at once.
        if n > self.MAX_LINES - 1:
            n = self.MAX_LINES - 1
        # Make sure there's enough empty space for the choices or free text input.
        max_end_lines = self.MAX_LINES - n
        end_lines = len(lines) % self.MAX_LINES
        if end_lines == 0:
            end_lines = self.MAX_LINES
        diff = end_lines - max_end_lines
        if diff <= 0:
            return lines
        return (
                lines[: n - self.MAX_LINES]
                + [""] * (self.MAX_LINES - diff)
                + lines[n - self.MAX_LINES:]
        )

    def split_line_if_too_long(self, line: str) -> list[str]:
        line = line.strip()
        if len(line) == 0:
            return [""]
        if len(line) <= self.LINE_MAX_CHARS:
            return [line]
        lines = []
        ln = ""
        for w in line.split(" "):
            if len(ln) + len(w) + 1 > self.LINE_MAX_CHARS:
                lines.append(ln)
                ln = ""
            ln += w + " "
        if len(ln) > 0:
            lines.append(ln)
        return lines

    def get_text_objs(self, lines: list[str]) -> list[TextObj]:
        text_objs = []
        for i in range(len(lines)):
            if self.game.is_server:
                obj = TextObj("", headless=True)
            else:
                obj = TextObj(
                    "",
                    x=0,
                    y=self.LINE_DISTANCE * i,
                    col=self.TEXT_COLOR,
                    font=gfx.FONT_PIXEL[self.TEXT_SIZE],
                )
            text_objs.append(obj)
        return text_objs

    def get_choice_objs(self, choices) -> list[TextObj]:
        choice_objs = []
        n = len(choices)
        if n > self.MAX_LINES - 1:
            n = self.MAX_LINES - 1
        for i, text in enumerate(choices):
            if self.game.is_server:
                o = TextObj(text, headless=True)
            else:
                o = TextObj(
                    text,
                    x=TEXT_X,
                    y=self.LINE_DISTANCE
                    * ((i % (self.MAX_LINES - 1)) + self.MAX_LINES - n),
                    col=self.TEXT_COLOR,
                    font=gfx.FONT_PIXEL[self.TEXT_SIZE],
                )
            choice_objs.append(o)
        return choice_objs

    def get_free_input_obj(self) -> TextObj:
        l = len(self.lines) + len(self.remaining_lines)
        if self.game.is_server:
            return TextObj("", headless=True)
        return TextObj(
            "",
            x=0,
            y=self.TEXT_Y - self.LINE_DISTANCE,
            col=self.TEXT_COLOR,
            font=gfx.FONT_PIXEL[self.TEXT_SIZE],
            allow_input=True,
            observer_hack=self.game.endpoint_type == venator.EndpointType.SPECTATOR,
        )

    def scroll(self):
        self.t += constants.TICK_S
        chars_to_show = int(floor(self.t * self.CHARS_PER_SECOND))
        for i, l in enumerate(self.text_objs):
            l = self.lines[i]
            t = self.text_objs[i]
            if chars_to_show >= len(l):
                t.text = l
                chars_to_show -= len(l)
                if i + 1 == len(self.text_objs):
                    # All text is shown now
                    self.done_scrolling = True
            else:
                t.text = l[0:chars_to_show]
                chars_to_show = 0
                break

    def tick(self, newly_pressed_keys):
        self.more_arrow_time += constants.TICK_S
        while self.more_arrow_time > 10:
            self.more_arrow_time -= 10

        if self.done_scrolling:
            if self.get_close_key() in newly_pressed_keys:
                if len(self.remaining_lines) > 0:
                    # Show next batch of text
                    self.t = 0
                    self.done_scrolling = False
                    self.lines = self.remaining_lines[: self.MAX_LINES]
                    self.remaining_lines = self.remaining_lines[self.MAX_LINES:]
                    self.text_objs = self.get_text_objs(self.lines)
                else:
                    # All done, close the textbox
                    self.done_fun()
                    if self.process_fun is not None:
                        self.process_fun(self.text_input.text.replace("\n", ""))
            elif self.choices_active():
                if Keys.W in newly_pressed_keys:
                    self.selection = max(0, self.selection - 1)
                    self.text_input.text = self.choices[self.selection]
                if Keys.S in newly_pressed_keys:
                    self.selection = min(len(self.choices) - 1, self.selection + 1)
                    self.text_input.text = self.choices[self.selection]
            elif self.free_text_active():
                if not self.text_input_appeared:
                    # Auto-select input box on appearance.
                    self.text_input_appeared = True
                    if not self.game.is_server:
                        self.text_input._active = True
        elif self.from_server and self.text_objs is None:
            pass  # Wait for text from server.
        elif Keys.E in newly_pressed_keys:
            # Fast-forward all remaining text
            self.done_scrolling = True
            for i in range(len(self.text_objs)):
                self.text_objs[i].text = self.lines[i]
        else:
            self.scroll()

    def draw(self):
        scale = gfx.GLOBAL_WINDOW.scale
        imgui.set_next_window_position(scale*self.BG_X, scale*self.BG_Y)
        imgui.set_next_window_size(scale*(self.bg.width+20), scale*(self.bg.height+20))
        with imgui.begin("textbox",
                         flags=imgui.WINDOW_NO_DECORATION | imgui.WINDOW_NO_NAV | imgui.WINDOW_NO_BACKGROUND):
            self.bg.draw()
            if self.from_server and self.text_objs is None:
                # Wait for text from server.
                return
            for t in self.text_objs:
                t.draw()
            if self.choices_active():
                self.draw_choices()
                self.draw_more_arrow()
            elif self.free_text_active():
                self.text_input.draw()
            else:
                self.draw_more_arrow()

    def set_text_from_server(self, text, choices, free_text):
        logging.info(f'Chat: "{text}"')
        self.choices = choices
        self.free_text = free_text
        self.init_text(text, choices, free_text)
        # Determine which callbacks should be invoked
        callbacks = [cb[1] for cb in self.response_callbacks.items() if cb[0] in text]
        if len(self.choices) > 0 or self.free_text:
            # Wait for the next message once this one's done.
            def next_textbox(resp: str):
                self.game.display_textbox(
                    from_server=True,
                    response_callbacks=self.response_callbacks)

            self.process_fun = next_textbox
        elif len(callbacks) > 0:
            if len(callbacks) > 1:
                logging.error("Multiple callbacks apply to this message, only invoking first one")
            self.process_fun = callbacks[0]
        else:
            self.process_fun = None

    def choices_active(self) -> bool:
        return (
                self.done_scrolling
                and len(self.remaining_lines) == 0
                and len(self.choice_objs) > 0
        )

    def free_text_active(self) -> bool:
        return (
                self.done_scrolling
                and len(self.remaining_lines) == 0
                and self.free_text
        )

    def get_close_key(self):
        if self.free_text_active():
            return Keys.ENTER
        return Keys.E

    def draw_choices(self):
        i = 0
        n = self.MAX_LINES - 1
        for c in self.choice_objs:
            if len(self.choice_objs) <= n or (i // n) == (self.selection // n):
                c.draw()
            i += 1
        imgui.set_cursor_pos(imgui.Vec2(gfx.GLOBAL_WINDOW.scale * TEXT_X,
                                        gfx.GLOBAL_WINDOW.scale * (self.choice_objs[self.selection].y+self.LINE_DISTANCE-7)))
        self.choice_arrow.draw()

    def draw_more_arrow(self):
        if int(floor(self.more_arrow_time * 2)) % 2 != 0:
            return
        scale = gfx.GLOBAL_WINDOW.scale
        if self.choices_active():
            n = self.MAX_LINES - 1
            if (
                    len(self.choice_objs) > n
                    and len(self.choice_objs) - self.selection >= n
            ):
                imgui.set_cursor_pos(imgui.Vec2(scale*800, scale*(self.bg.height-40)))
                self.more_arrow.draw()
            return
        if self.done_scrolling:
            imgui.set_cursor_pos(imgui.Vec2(scale*800, scale*(self.bg.height-40)))
            self.more_arrow.draw()
