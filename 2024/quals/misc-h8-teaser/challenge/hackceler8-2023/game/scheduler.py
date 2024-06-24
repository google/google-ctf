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

import time

class TickScheduler:
    """
        Tick Scheduler that is lag resistant. It calculates the amount of game
        ticks that should have happened since it was started, allowing faster
        'catch up' ticks. The amount of allowed 'catch up' ticks can be limited.
    """

    def __init__(self, tps, max_lag=None):
        # ticks per second
        self._tps = tps

        # maximum lag in ticks. the client will only be able to
        # catch up to this amount of ticks regardless of how big
        # the lag was.
        self._max_lag = max_lag

        # Time where the measurement started.
        self._start_time = 0

        # Ticks since the start of the measurement, 'max lag' adjusted.
        self._tick_counter = 0

    def start(self):
        assert self._start_time == 0, "TickScheduler already started"
        self._start_time = time.time()

    def get_sleep_time(self):
        assert self._start_time != 0, "TickScheduler not started"
        expected_ticks = (time.time() - self._start_time) * self._tps
        # # of ticks that we're currently lagging behind. 0 if none.
        ticks_delta = expected_ticks - self._tick_counter

        if self._max_lag and ticks_delta > self._max_lag:
            # Lag too big, adjust _tick_counter
            self._tick_counter += ticks_delta - self._max_lag

        # If we are lagging at least one tick behind, do not sleep.
        if ticks_delta >= 1.0:
            return 0.0

        # Otherwise calculate time we should based on the ticks per second.
        return (-ticks_delta + 1.0) / self._tps

    def tick(self):
        assert self._start_time != 0, "TickScheduler not started"
        self._tick_counter += 1
        
