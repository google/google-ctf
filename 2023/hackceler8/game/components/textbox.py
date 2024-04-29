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
from math import floor

import arcade
import arcade.gui
import constants


class HeadlessTextObj:
    # Text box objects that don't have any graphical content. Used for server mode.
    def __init__(self, text: str):
        self.text = text


class Textbox:
    bg = arcade.load_texture("resources/textbox/bg.png")
    more_arrow = arcade.load_texture("resources/textbox/more-arrow.png")
    choice_arrow = arcade.load_texture("resources/textbox/choice-arrow.png")

    CHARS_PER_SECOND = 20
    BG_SCALE = 5
    BG_X = bg.width * BG_SCALE * 0.5
    BG_Y = bg.height * BG_SCALE * 0.5
    TEXT_X = 30
    TEXT_Y = bg.height * BG_SCALE - 90
    TEXT_COLOR = arcade.color_from_hex_string("#e0f8cf")
    TEXT_SIZE = 30
    LINE_DISTANCE = 60
    LINE_MAX_CHARS = 42
    MAX_LINES = 5

    def __init__(self, game, text: str, done_fun, choices=None,
                 free_text=False, from_llm=False, process_fun=None):
        if choices is None:
            choices = []

        self.game = game
        self.done_fun = done_fun
        self.free_text = free_text
        self.from_llm = from_llm
        self.process_fun = process_fun
        self.choices = choices
        self.selection = 0

        if free_text and len(choices) > 0:
            logging.error("Both free text and multiple choice specified")

        self.lines = []
        self.remaining_lines = []
        self.choice_objs = []
        self.text_input = None
        self.ui_manager = None

        self.text_input_appeared = False
        self.t = 0
        self.done_scrolling = False
        self.more_arrow_time = 0
        if from_llm:
            # Wait for the LLM's text.
            self.text_objs = None
            if self.game.is_server or self.game.net is None:
                self.game.query_llm(text)
        else:
            self.init_text(text, choices, free_text)
        if not from_llm:
            logging.info(f"Chat: \"{text}\"")

    def init_text(self, text: str, choices, free_text):
        self.lines = self.get_lines(text, choices, free_text)
        self.remaining_lines = self.lines[self.MAX_LINES:]
        self.lines = self.lines[:self.MAX_LINES]
        self.text_objs = self.get_text_objs(self.lines)
        self.choice_objs = self.get_choice_objs(self.choices)
        self.text_input = self.get_free_input_obj()
        if len(self.choices) > 0:
            self.text_input.text = self.choices[self.selection]
        if free_text and not self.game.is_server:
            self.ui_manager = arcade.gui.UIManager()
            self.ui_manager.enable()
            self.ui_manager.add(self.text_input)

    def get_lines(self, text: str, choices, free_text) -> list[str]:
        initial_lines = text.strip().split("\n")
        lines = []
        for l in initial_lines:
            lines += self.split_line_if_too_long(l)
        n = 1 if free_text else len(choices)
        return self.make_space_for_input(lines, n)

    def make_space_for_input(self, lines, n):
        # Only MAX_LINES-1 choices displayed at once.
        if n > self.MAX_LINES-1:
            n = self.MAX_LINES-1
        # Make sure there's enough empty space for the choices or free text input.
        max_end_lines = self.MAX_LINES - n
        end_lines = len(lines) % self.MAX_LINES
        if end_lines == 0:
            end_lines = self.MAX_LINES
        diff = end_lines - max_end_lines
        if diff <= 0:
            return lines
        return lines[:n - self.MAX_LINES] + [""] * (self.MAX_LINES - diff) + lines[
                                                                             n - self.MAX_LINES:]

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

    def get_text_objs(self, lines: list[str]):
        text_objs = []
        for (i, line) in enumerate(lines):
            if self.game.is_server:
                o = HeadlessTextObj("")
            else:
                o = arcade.Text("",
                                self.TEXT_X,
                                self.TEXT_Y - self.LINE_DISTANCE * i,
                                self.TEXT_COLOR,
                                self.TEXT_SIZE,
                                font_name=constants.FONT_NAME)
            text_objs.append(o)
        return text_objs

    def get_choice_objs(self, choices):
        choice_objs = []
        n = len(choices)
        if n > self.MAX_LINES-1:
            n = self.MAX_LINES-1
        for (i, text) in enumerate(choices):
            if self.game.is_server:
                o = HeadlessTextObj(text)
            else:
                o = arcade.Text(text,
                                self.TEXT_X + 35,
                                self.TEXT_Y - self.LINE_DISTANCE * (
                                        (i % (self.MAX_LINES-1)) + self.MAX_LINES - n),
                                self.TEXT_COLOR,
                                self.TEXT_SIZE,
                                font_name=constants.FONT_NAME)
            choice_objs.append(o)
        return choice_objs

    def get_free_input_obj(self):
        l = len(self.lines) + len(self.remaining_lines)
        if self.game.is_server:
            return HeadlessTextObj("")
        return arcade.gui.UIInputText(self.TEXT_X,
                                      self.TEXT_Y - 5 - self.LINE_DISTANCE * (
                                              l % self.MAX_LINES),
                                      1200,
                                      self.TEXT_SIZE + 10,
                                      "",
                                      constants.FONT_NAME,
                                      self.TEXT_SIZE,
                                      self.TEXT_COLOR)

    def scroll(self):
        self.t += constants.TICK_S
        chars_to_show = int(floor(self.t * self.CHARS_PER_SECOND))
        for (i, l) in enumerate(self.text_objs):
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
                    self.lines = self.remaining_lines[:self.MAX_LINES]
                    self.remaining_lines = self.remaining_lines[self.MAX_LINES:]
                    self.text_objs = self.get_text_objs(self.lines)
                else:
                    # All done, close the textbox
                    self.done_fun()
                    if self.process_fun is not None:
                        self.process_fun(self.text_input.text.replace("\n", ""))
            elif self.choices_active():
                if arcade.key.W in newly_pressed_keys:
                    self.selection = max(0, self.selection - 1)
                    self.text_input.text = self.choices[self.selection]
                if arcade.key.S in newly_pressed_keys:
                    self.selection = min(len(self.choices) - 1, self.selection + 1)
                    self.text_input.text = self.choices[self.selection]
            elif self.free_text_active():
                if not self.text_input_appeared:
                    # Auto-select input box on appearance.
                    self.text_input_appeared = True
                    if not self.game.is_server:
                        self.text_input._active = True
        elif self.from_llm and self.text_objs is None:
            pass # Wait for text from server.
        elif arcade.key.E in newly_pressed_keys:
            # Fast-forward all remaining text
            self.done_scrolling = True
            for i in range(len(self.text_objs)):
                self.text_objs[i].text = self.lines[i]
        else:
            self.scroll()

    def draw(self):
        self.bg.draw_scaled(self.BG_X, self.BG_Y, self.BG_SCALE)
        if self.from_llm and self.text_objs is None:
            # Wait for text from server.
            return
        for t in self.text_objs:
            t.draw()
        if self.choices_active():
            self.draw_choices()
            self.draw_more_arrow()
        elif self.free_text_active():
            self.draw_free_text_input()
        else:
            self.draw_more_arrow()

    def set_text_from_server(self, text):
        logging.info(f"Chat: \"{text}\"")
        self.init_text(text, self.choices, self.free_text)

    def choices_active(self) -> bool:
        return self.done_scrolling and len(self.remaining_lines) == 0 and len(
            self.choice_objs) > 0

    def free_text_active(self) -> bool:
        return self.done_scrolling and len(self.remaining_lines) == 0 and self.free_text

    def get_close_key(self):
        if self.free_text_active():
            return arcade.key.ENTER
        return arcade.key.E

    def draw_choices(self):
        i = 0
        n = self.MAX_LINES-1
        for c in self.choice_objs:
            if len(self.choice_objs) <= n or (i//n) == (self.selection//n):
                c.draw()
            i += 1
        self.choice_arrow.draw_scaled(42, self.choice_objs[self.selection].y + 17,
                                      self.BG_SCALE)

    def draw_free_text_input(self):
        self.ui_manager.draw()
        # Draw a border
        arcade.draw_lrtb_rectangle_outline(
            self.text_input.x - 4, self.text_input.x + self.text_input.width + 4,
            self.text_input.y + self.text_input.height + 4, self.text_input.y - 4,
            color=self.TEXT_COLOR, border_width=4)

    def draw_more_arrow(self):
        if int(floor(self.more_arrow_time * 2)) % 2 != 0:
            return
        if self.choices_active():
            n = self.MAX_LINES-1
            if len(self.choice_objs) > n and len(self.choice_objs) - self.selection >= n:
                self.more_arrow.draw_scaled(1200, 50, self.BG_SCALE)
            return
        if self.done_scrolling:
            self.more_arrow.draw_scaled(1200, 50, self.BG_SCALE)
