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

from game.components.npc.trapped_npc import Quackington, Jessse,  Casher, Raibbit
from game.components.npc.password_npc import EasyPasswordNpc
from game.components.npc.chest_npc import Chest, ChestTrasher

NPC_TYPES = {
    "easy_password_npc": EasyPasswordNpc,
    "chest_npc": Chest,  # This is not actually a NPC but close enough
    "trapped_quackington_npc": Quackington,
    "trapped_jessse_npc": Jessse,
    "trapped_trasher_npc": ChestTrasher,
    "trapped_casher_npc": Casher,
    "trapped_raibbit_npc": Raibbit,
}
