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

import serialize
import utils
import types
import sys

class PersistentState(serialize.SerializableObject):
    """Stores state that persists for a player across loads/saves."""
    def __init__(self):
        super().__init__()
        self.obtained_flags = {}
        self.game_complete = False


# Code for tracking if the persistent state has been changed and needs to be updated
class PersistentStateModule(types.ModuleType):
    def __init__(self):
        super().__init__(__name__, __doc__)
        self._persistent_state = None
        self._state_modification_sentinel = [False]
        self.PersistentState = PersistentState

    def persistent_state_ready(self):
        return self._persistent_state is not None

    @property
    def persistent_state(self):
        if self._persistent_state is None:
            raise RuntimeError("persistent_state cannot be accessed during setup - it has not yet been decrypted by the server. You can use persistent_state_ready() to check.")
        return utils.ModifiedProxy(self._persistent_state, self._state_modification_sentinel)

    @persistent_state.setter
    def persistent_state(self, value):
        self._state_modification_sentinel[0] = True
        self._persistent_state = value

    @property
    def modified(self):
        return self._state_modification_sentinel[0]

    @modified.setter
    def modified(self, value):
        self._state_modification_sentinel[0] = value

sys.modules[__name__] = PersistentStateModule()