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

import logging

from components.weapon_systems import cannon
from components.weapon_systems import gun
from components.weapon_systems import poison

weapon_types = {
    "gun": gun.Gun,
    "cannon": cannon.Cannon,
    "poison": poison.Poison
}


def parse_weapon(props: dict, coords):
    needed_props = [
        "type",
        "collectable"
    ]
    for i in needed_props:
        if i not in props:
            logging.critical(f"Missing property {i}")
            return None
    logging.debug(f"Adding new weapon type {props['type']}")
    return weapon_types[props["type"]](coords, props["type"], props["collectable"], props.get("flipped", False), props.get("damage", None))
