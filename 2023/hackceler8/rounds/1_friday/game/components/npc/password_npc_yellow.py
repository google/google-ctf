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
from components import magic_items
from .password_npc import PasswordNpc

class PasswordNpcYellow(PasswordNpc):
    ENCRYPTED_PASSWORD = "r%M}'QGb!a"

    def __init__(self, coords, name, walk_data):
        item = magic_items.Item(coords=None,
                                name="boots",
                                display_name="Boots", wearable=True)
        super().__init__("Yellow", self._password_correct, item,
                         "resources/NPCs/Snake_NPC_Yellow.tmx",
                         coords, name, walk_data)

    def _password_correct(self, passwd):
        return self._encrypt(passwd) == self.ENCRYPTED_PASSWORD

    def _encrypt(self, passwd):
        enc = codecs.encode(passwd, 'rot_13')
        enc = ''.join([chr(ord(b)^0x14) for b in enc]) # For extra security
        return enc
