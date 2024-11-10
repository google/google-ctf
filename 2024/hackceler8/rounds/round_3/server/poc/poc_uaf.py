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
    start_stars = replay.game.match_flags.stars()
    replay.enter_map("cloud")

    def pickup_gem(x,y):
        replay.teleport(x, y)
        replay.enqueue([''] * 120)

    # 1
    pickup_gem(1200, 3024)
    yield

    # 2
    pickup_gem(800, 3152)
    yield

    # 3
    pickup_gem(2080, 2352)
    yield

    # 4
    pickup_gem(1360, 2320)
    yield

    # 5
    pickup_gem(1024, 3152)
    yield

    # 6
    pickup_gem(2608, 3152)
    yield

    # 7
    pickup_gem(1936, 2816)
    yield

    # 8
    pickup_gem(608, 3152)
    yield

    # 9
    pickup_gem(2688, 2816)
    yield

    # 10
    pickup_gem(1568, 2896)
    yield

    # 11
    pickup_gem(2752, 2624)
    yield

    # 12
    pickup_gem(1680, 2448)
    yield

    # 13
    pickup_gem(2432, 2480)
    yield

    # 14
    pickup_gem(2112, 3152)
    yield

    # 15
    pickup_gem(3008, 2704)
    yield

    replay.enter_map("beach")
    replay.teleport(215, 920)
    for i in range(100):
        replay.enqueue(['e'] * 1)
        replay.enqueue(['a'] * 1)

    yield

    replay.enqueue(['e'] * 1)
    yield

    # Free the NPC using the key.
    replay.teleport(5344, 720)
    replay.enqueue([''] * 89 + ['L'] * 6 + ['La'] * 65 + ['L'] * 17 + ['Ld'] * 17 + ['L'] * 14 + ['Le'] * 4 + ['L'] * 5 + ['Ld'] * 60 + ['e'] * 3 + [''] * 3 + ['e'] * 3 + [''] * 4 + ['e'] * 3 + [''] * 3 + ['e'] * 4 + [''] * 39 + ['d'] * 33 + ['da'] + ['a'] * 6 + [''] * 34 + ['￩'] * 82)
    yield
    # Make sure we freed the NPC.
    assert replay.game.match_flags.stars() > start_stars
    replay.exit()


if __name__ == '__main__':
    replay = ReplayHelper()
    replay.start_game(replay_iter_func)
