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

from .enemy import Block, Crab, Urchin, Golem, Orc, Vulture, Eagle, Octopus, Siren

ENEMY_TYPES = {
    "block_enemy": Block,
    "crab_enemy": Crab,
    "urchin_enemy": Urchin,
    "golem_enemy": Golem,
    "orc_enemy": Orc,
    "vulture_enemy": Vulture,
    "eagle_enemy": Eagle,
    "octopus_enemy": Octopus,
    "siren_enemy": Siren,
}
