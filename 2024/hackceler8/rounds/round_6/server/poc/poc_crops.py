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
    # Simulate player walking to leve
    replay.enqueue([''] * 540)
    yield
    replay.enter_map("beach")
    replay.enqueue(['Ld'] * 225)
    # pick up crops
    replay.enqueue(['t'] * 1)
    replay.enqueue(['Ld'] * 30)
    # =======================
    #
    # we want to plant at tick 1800
    replay.enqueue([''] * 1004)
    yield
    # logging.info(replay.game.count)
    # plant crops
    replay.enqueue(['t'] * 1)
    replay.enqueue([''] * 358)
    # collect crops
    replay.enqueue(['t'] * 1)
    yield

    # wait out the hail and snow
    replay.enqueue([''] * 900)
    yield
    # plant crops
    replay.enqueue(['t'] * 1)
    replay.enqueue([''] * 1078)
    replay.enqueue(['t'] * 1)
    yield
    replay.enqueue([''] * 540)
    yield
    replay.enqueue(['t'] * 1)
    replay.enqueue([''] * 358)
    # collect crops
    replay.enqueue(['t'] * 1)
    yield
    replay.enqueue([''] * 200)

    replay.teleport(4432,930)
    # account for the time to walk there
    replay.enqueue(['']*1200)

    yield
    logging.info("We're getting the crops with this one")
    # replay.enqueue([''] * 900)
    # yield
    # plant crops
    replay.enqueue(['t'] * 1)
    replay.enqueue([''] * 398)
    replay.enqueue(['t'] * 1)
    yield
    replay.enqueue([''] * 360)
    yield
    replay.enqueue(['t'] * 1)
    replay.enqueue([''] * 358)
    replay.enqueue(['t'] * 1)
    yield
    replay.enqueue([''] * 180)
    replay.enqueue(['t'] * 1)
    replay.enqueue([''] * 1438)
    replay.enqueue(['t'] * 1)
    yield

    replay.teleport(5328,912)

    # time to reach the boss
    replay.enqueue([''] * 1000)
    yield
    for i in range(10):
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
