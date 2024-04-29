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

from collections import deque

def sleep_ticks(n):
    for i in range(n):
        yield

class CoroutineSystem():
    def __init__(self, init):
        self.coroutines = init
        self.to_add = deque()
        self.to_remove = deque()

    def add(self, x):
        self.to_add.append(x)

    def remove(self, x):
        self.to_remove.append(x)

    def tick(self):
        for i in self.coroutines:
            try:
                next(i)
            except StopIteration:
                self.remove(i)
        while len(self.to_add) > 0:
            self.coroutines.append(self.to_add.pop())
        while len(self.to_remove) > 0:
            self.coroutines.remove(self.to_remove.pop())
