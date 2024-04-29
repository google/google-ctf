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
from components.music_note import MusicNote
from math import floor

import arcade
import arcade.gui
import constants
import pyglet.media.synthesis
import pytiled_parser


class JamSession:
    KEYS = {
        arcade.key.KEY_1: 0,
        arcade.key.KEY_2: 1,
        arcade.key.KEY_3: 2,
        arcade.key.KEY_4: 3,
        arcade.key.KEY_5: 4,
        arcade.key.KEY_6: 5,
        arcade.key.KEY_7: 6,
        arcade.key.KEY_8: 7,
        arcade.key.KEY_9: 8,
        arcade.key.KEY_0: 9,
        arcade.key.MINUS: 10,
        arcade.key.EQUAL: 11,
    }

    TEXT_X = 30
    TEXT_Y = 100
    TEXT_COLOR = arcade.color_from_hex_string("#e0f8cf")
    TEXT_SIZE = 30

    def __init__(self, game, verify_callback, end_callback=None):
        self.game = game
        self.sequence = []
        self.current_pressed_key = None
        self.current_pressed_key_ticks = 0
        self.current_player = None
        self.verify_callback = verify_callback
        self.end_callback = end_callback
        self.music_notes = []
        # Will be overwritten
        self.player = None

    def _register_current_key(self, key, newly_pressed_keys, octave):
        # Ignore silence if the song did not start yet.
        if self.current_pressed_key is None and key is None and len(self.sequence) == 0:
            return

        if key is not None:
            tone_no = JamSession.KEYS.get(key) + octave * 12
            if key in newly_pressed_keys:
                self._add_music_note()
        else:
            tone_no = None

        if tone_no != self.current_pressed_key:
            if self.current_pressed_key_ticks > 0:
                self.sequence.append(
                    (self.current_pressed_key, self.current_pressed_key_ticks))

            if self.current_player is not None:
                self.current_player.delete()

            self.current_pressed_key = tone_no
            self.current_pressed_key_ticks = 1

            if tone_no is not None:
                base = 1.05946
                freq = 440.0 * pow(base, tone_no)
                self.current_player = pyglet.media.synthesis.Sine(10,
                                                                  frequency=freq).play()
        else:
            self.current_pressed_key_ticks += 1

    def _add_music_note(self):
        self.music_notes.append(
            MusicNote(pytiled_parser.OrderedPair(self.player.x, self.player.y)))

    def tick(self, pressed_keys, newly_pressed_keys):
        for m in list(self.music_notes):
            m.tick()
            if m.sprite.alpha <= 0:
                self.music_notes.remove(m)
        played_tones = pressed_keys.intersection(JamSession.KEYS.keys())

        octave = 0
        if arcade.key.SPACE in pressed_keys:
            octave += 1
        if arcade.key.RETURN in pressed_keys:
            octave += 1

        if len(played_tones) > 1:
            logging.info("The instrument makes weird sounds")
            self._register_current_key(None, newly_pressed_keys, 0)
        elif len(played_tones) == 0:
            self._register_current_key(None, newly_pressed_keys, 0)
        else:
            self._register_current_key(played_tones.pop(), newly_pressed_keys, octave)

        # Check if we ended the jam session
        success = self.verify_callback(self.sequence)
        if arcade.key.ESCAPE in pressed_keys or success:
            if self.end_callback:
                self.end_callback(success)
            self.game.jam_session = None

    def draw(self):
        if self.game.is_server:
            return
        arcade.draw_text("You're playing the song of your people",
                         self.TEXT_X,
                         self.TEXT_Y,
                         self.TEXT_COLOR,
                         self.TEXT_SIZE,
                         font_name=constants.FONT_NAME)

    def draw_notes(self):
        if self.game.is_server:
            return
        for m in list(self.music_notes):
            m.draw()
