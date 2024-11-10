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
import logging

from poc.helper import ReplayHelper


def replay_iter_func(replay):
    start_stars = replay.game.match_flags.stars()
    replay.enter_map("ocean")
    replay.enqueue(['Lds'] * 180 )

    yield

    replay.enqueue(['Lds'] * 90)
    replay.enqueue(['wd'] * 10)
    replay.enqueue(['Lds'] * 180)

    replay.enqueue(['Lds'] * 880)
    replay.enqueue([''] * 30)
    yield

    # get star
    for i in range(4):
        replay.enqueue(['e'] * 1)
        replay.enqueue([''] * 1)
        yield

    replay.enqueue([''] * 90)
    yield

    assert replay.game.match_flags.stars() > start_stars

    replay.exit()


if __name__ == '__main__':
    replay = ReplayHelper()
    replay.start_game(replay_iter_func)
