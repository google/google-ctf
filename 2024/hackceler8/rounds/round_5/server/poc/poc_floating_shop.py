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

# Fallback if doesn't work:
# python3 -m poc.record --map=beach --pos=5245,900
# Buy 100 cookie, sell 100 cookie, buy 1 star
def replay_iter_func(replay):
    start_stars = replay.game.match_flags.stars()
    replay.enter_map("beach")
    replay.teleport(5334, 920)

    def pause():
        replay.enqueue([''] * 100)

    replay.enqueue(['d'] * 100)
    replay.enqueue(['e'] * 1)
    pause()
    replay.enqueue(['e'] * 1)
    pause()

    # Buy
    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue([('e', 'Cookie'), 'N'])
    replay.enqueue([('e', '100'), 'N'])

    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue(['s'] * 1)
    pause()

    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue([('e', 'Cookie'), 'N'])
    replay.enqueue([('e', 'Cookie'), 'N'])
    replay.enqueue([('e', '100'), 'N'])
    pause()
    pause()


    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue(['e'] * 1)
    pause()

    replay.enqueue(['s'] * 1)
    pause()

    replay.enqueue([('e', 'Stars'), 'N'])
    replay.enqueue([('e', '1'), 'N'])
    pause()
    yield

    replay.enqueue(['e'] * 1)
    pause()

    yield

    assert replay.game.match_flags.stars() > start_stars
    replay.exit()


if __name__ == '__main__':
    replay = ReplayHelper()
    replay.start_game(replay_iter_func)
