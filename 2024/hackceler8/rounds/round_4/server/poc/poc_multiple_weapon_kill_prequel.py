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
from time import sleep



def replay_iter_func(replay):
  start_stars = replay.game.match_flags.stars()
  replay.enter_map("ruins")
  replay.enqueue([''] * 87 + ['a'] * 4 + [''] + ['d'] * 3 + ['da'] * 2 + ['a'] * 2 + ['da'] + ['d'] * 2 + ['da'] + ['a'] * 2 + ['da'] + ['d'] * 2 + ['da'] + ['a'] * 3 + ['d'] * 3 + ['da'] + ['a'] * 4 + [''] * 19 + ['a'] * 20 + ['aL'] * 26 + ['waL'] * 8 + ['aL'] * 18 + ['a'] * 9 + [''] * 11 + ['a'] * 17 + [''] * 23 + ['a'] * 5 + ['aL'] * 7 + ['a'] * 7 + ['da'] + ['d'] * 34 + ['da'] * 5 + ['daL'] * 12 + ['a'] * 2 + ['aL'] * 12 + ['a'] * 35 + ['a '] + ['da '] + ['d '] + ['d'] * 3 + ['wd'] * 3 + ['wdL'] * 13 + ['dL'] + ['d'] * 41 + ['dL'] * 28 + ['d'] * 4 + [''] * 40 + ['w'] * 6 + ['wL'] * 18 + ['wdL'] * 18 + ['d'] * 5 + [''] * 5 + ['d'] * 6 + [''] * 12 + ['a'] * 4 + [''] * 9 + ['d'] * 3 + [''] * 68 + ['L'] * 19 + ['wL'] * 9 + ['wdL'] * 31 + ['wL'] + ['L'] * 8 + [''] * 34 + ['w'] * 3 + ['wa'] * 4 + ['w'] + ['wd'] * 5 + ['w'] * 10 + ['wdL'] * 18 + ['dL'] * 4 + ['d'] * 3 + [''] + ['L'] + ['aL'] + ['waL'] * 35 + ['wa'] * 2 + ['a'] * 46 + ['wa'] * 2 + ['w'] * 4 + [''] * 3 + [' '] + [''] * 57 + ['a'] * 6 + [''] * 41 + [' '] * 4 + [''] * 15 + ['w'] * 5 + [''] * 4 + [' '] * 4 + [''] * 84 + [' '] * 4 + [''] * 22 + ['w'] * 3 + [''] * 4 + [' '] * 4 + [''] * 58 + ['a'] * 6 + ['aL'] * 31 + ['a'] * 8 + [''] * 15 + ['a'] * 7 + [''] + ['a'] * 10)
  replay.enqueue(['aq']*20)
  yield


  for i in range(180):
    # Beginning of logic to switch and drop non-colored gun.
    normal_guns = [i for i in replay.game.player.weapons if i.name == "gun"]
    if (len(normal_guns) != 0):
      initial_colored_equipped = [i.name for i in replay.game.player.weapons if i.equipped and i.name.endswith("_gun")]
      if len(initial_colored_equipped) > 0:
        replay.enqueue(['p'])
      while True:
        equipped = [i for i in replay.game.player.weapons if i.equipped]
        if len(equipped) == 0 and len(replay.game.player.weapons) != 0:
          replay.enqueue(['s'])
          yield
        elif len(equipped) > 0 and equipped[0].name.endswith("_gun"):
          if replay.game.player.weapons[-1].name == equipped[0].name:
            replay.enqueue(['w', ''])
          else:
            replay.enqueue(['s', ''])
          yield
        else:
          break
      if len(initial_colored_equipped) > 0:
        replay.enqueue(['pq', ''])
      else:
        replay.enqueue(['q', ''])
      yield
    # Ending of logic to switch and drop non-colored gun.

    if replay.game.player.y > 2010:
      replay.enqueue([' ', ''])
    elif replay.game.player.y > 1950:
      replay.enqueue([' ', ''])
    elif replay.game.player.y == 1869:
      replay.enqueue([' '])
    else:
      replay.enqueue([''])
    yield

  all_weapons = ['red_gun', 'blue_gun', 'green_gun', 'orange_gun']
  for i in replay.game.player.weapons:
    if i.name in all_weapons:
      all_weapons.remove(i.name)

  assert len(all_weapons) == 0

  replay.teleport(561, 2601)
  replay.enqueue([''] + ['e'] + [''] + ['e'] + [''] + ['e'] + ['']*120)
  yield
  assert replay.game.match_flags.stars() > start_stars
  replay.exit()

if __name__ == '__main__':
  replay = ReplayHelper()
  replay.start_game(replay_iter_func)
