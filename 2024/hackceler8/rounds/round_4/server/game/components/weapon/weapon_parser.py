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

import logging
from typing import Optional

from game.components.weapon import cannon
from game.components.weapon import gun
from game.components.weapon import ranged_rifle
from game.components.weapon.weapon import Weapon
from game.components.weapon import pencil
from game.components.weapon import poison

weapon_types = {"gun": gun.Gun,
                "red_gun": gun.RedGun,
                "blue_gun": gun.BlueGun,
                "brown_gun": gun.BrownGun,
                "orange_gun": gun.OrangeGun,
                "green_gun": gun.GreenGun,
                "cannon": cannon.Cannon,
                "pencil": pencil.Pencil,
                "poison": poison.Poison,
                "ranged_rifle": ranged_rifle.RangedRifle,
                }


def parse_weapon(props: dict, coords) -> Optional[Weapon]:
    if "type" not in props:
        logging.critical(f"Missing property 'type'")
        return None
    logging.debug(f"Adding new weapon type {props['type']}")
    return weapon_types[props["type"]](coords, props["type"])
