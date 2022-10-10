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

import persistent_state
from gametree import *
import os


class AndGate(Component):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.coordinates = {}
        self.map = None
        self.active_inputs = []
        self.active_out = False
        self.expected_inputs = 2

    def on_activation(self, source):
        if source in self.active_inputs:
            self.active_inputs.remove(source)
        else:
            self.active_inputs.append(source)
        new_active_out = len(self.active_inputs) >= self.expected_inputs
        if self.active_out != new_active_out:
            self.ref.dispatch_to_components("on_activation", self)
            self.active_out = new_active_out

