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

from poc.helper import ReplayHelper


def replay_iter_func(replay):
    replay.enter_map("dialogue_boss")
    replay.teleport(810, 416)
    replay.enqueue([''] * 90)
    yield
    # Select "I know the spell"
    replay.enqueue(['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''])
    yield
    # Enter first option
    passwd = " "*32
    c_min = ord(' ') # smallest printable char
    c_max = ord('~') # largest printable char
    c_pos = 0
    while True:
        while not replay.game.textbox.free_text_active():
            replay.enqueue(['e'] + [''])
            yield
        replay.game.textbox.text_input.text = passwd
        replay.enqueue([''] + ['N'] + [''] + ['e'] + [''])
        yield
        print("XX", replay.game.textbox.text)
        while replay.game.textbox.text is None:
            replay.enqueue([''])
            yield
        txt = replay.game.textbox.text
        if "that's correct" in txt: # Found the correct password
            break
        # Get return code and position
        code = int(txt.split("Return code ")[1].split(" at position")[0])
        pos = int(txt.split("at position ")[1].split(".")[0])
        if pos > c_pos:
            c_pos = pos
            c_min = ord(' ')
            c_max = ord('~')
        char = ord(passwd[pos])
        if code == -1:
            c_min = char+1
        elif code == 1:
            c_max = char-1
        else:
            print("Unknown code", code)
            exit(1)
        char = (c_min+c_max) // 2
        passwd = passwd[:pos] + chr(char) + passwd[pos+1:]
        print("trying", passwd)
        replay.enqueue(['e'] + [''] + ['e'] + [''])
        replay.enqueue(['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''])
        yield

    # Scroll through destruction dialogue.
    replay.enqueue(['e'] + [''] + ['e'] + [''] + ['e'] + [''] + ['e'] + [''])
    # Wait for destruction.
    replay.enqueue(['']*300)
    yield

    # Check that the boss was defeated.
    found = False
    for f in replay.game.match_flags.flags:
        if f.name == "dialogue_boss" and f.collected_time > 0:
            found = True
            break
    assert found

    replay.exit()


if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)
