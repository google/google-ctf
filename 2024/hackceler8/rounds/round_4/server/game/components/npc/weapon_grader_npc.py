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

from game.engine import hitbox
from game.components.items import check_item_loaded
from .npc import Npc
grades = "ZYXWVUTSRQPONMLKJIHGFEDCBA"

class WeaponGraderNpc(Npc):
    def __init__(self, coords, **kwargs):
        super().__init__(coords=coords, scale=1, tileset_path="resources/NPCs/Snake_NPC_Green.h8t", **kwargs)
        rect = hitbox.Rectangle(coords.x - 15, coords.x + 15, coords.y - 25, coords.y + 25)
        self.update_hitbox(rect)
        self.graded = False

    def dialogue(self):
        if self.graded:
            self.display_textbox("I already graded your weaponssss, no takesies backsiessssss")
            return
        if len(self.game.player.weapons) <= 0:
            self.display_textbox("You have no itemsssss to grade!")
            return

        text = "Psssst! Do you want me to grade your weaponsssss?"

        def resp_process(resp: str):
            if resp == "Yes":
                self.graded = True
                grade_weapon()
            else:
                self.display_textbox("Oh, then why are you here?")

        def grade_weapon():
            txt = []
            for weapon in self.game.player.weapons:
                grade_i = min(weapon.kill_counter, len(grades) - 1)
                old_name = weapon.display_name
                weapon.display_name = grades[grade_i] + weapon.display_name
                txt.append("Weapon %s got grade %s" % (old_name, grades[grade_i]))
            self.display_textbox("\n".join(txt))
        self.display_textbox(text, choices=["Yes", "No"], process_fun=resp_process)
