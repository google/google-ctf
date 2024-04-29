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

import codecs
import subprocess
from components import magic_items
from .password_npc import PasswordNpc

class PasswordNpcBlue(PasswordNpc):
    def __init__(self, coords, name, walk_data):
        item = magic_items.Item(coords=None,
                                name="key_purple",
                                display_name="Purple key",
                                color="purple")
        super().__init__("Blue", self._password_correct, item,
                         "resources/NPCs/Snake_NPC_Blue.tmx",
                         coords, name, walk_data)

    def _password_correct(self, passwd):
        p = subprocess.run(["binaries/password_blue", passwd])
        return (p.returncode == 0)
