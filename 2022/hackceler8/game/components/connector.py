# Copyright 2022 Google LLC
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

from gametree import *


class Connector(Component):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def update_animation(self, frameset):
        pass

    def tick(self):
        pass

    def while_keys_held(self, keys):
        pass

    def on_activation(self, caller):
        if self.ref:
            self.ref.dispatch_to_components("on_activation", caller)

    def on_collision_enter(self, other):
        pass

    def while_colliding(self, other):
        pass

    def on_collision_exit(self, other):
        pass

    def duplicate(self, new_entity):
        pass
