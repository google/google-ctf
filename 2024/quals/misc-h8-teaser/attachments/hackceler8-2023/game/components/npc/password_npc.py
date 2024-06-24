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

from .npc import Npc
from engine import hitbox


class PasswordNpc(Npc):
    solved = {}

    def __init__(self, id, is_correct_fun, item, tileset_path, coords, name, walk_data):
        super().__init__(coords, name, walk_data, scale=1,
                         tileset_path=tileset_path)
        self.id = id
        self.is_correct_fun = is_correct_fun
        self.item = item
        outline = [
            hitbox.Point(coords.x - 15, coords.y - 25),
            hitbox.Point(coords.x + 15, coords.y - 25),
            hitbox.Point(coords.x + 15, coords.y + 25),
            hitbox.Point(coords.x - 15, coords.y + 25),
        ]
        self._update(outline)

    def dialogue(self):
        if PasswordNpc.solved.get(self.id, False):
            self.display_textbox(
                "That'ssss all I have to give to you.\nGo talk to ssssomeone else.")
            return

        text = "Psssst! Do you know the passssword?"

        def resp_process(resp: str):
            if resp == "YES":
                self.display_textbox("Then dissssclose it to me!", free_text=True,
                                     process_fun=password_check)
            else:
                self.display_textbox("Oh, that'sssss a shame.")

        def password_check(password: str):
            if self.is_correct_fun(password):
                if self.item is not None:
                    self.game.gather_items([self.item])
                PasswordNpc.solved[self.id] = True
                answer = "Yep, that'sssss correct! Here'ssss your reward!\n\nMew " \
                        "received *%s*!"
                self.display_textbox(answer % (
                    "Nothing" if (self.item is None) else self.item.display_name))
            else:
                self.display_textbox("No, that'sssss not it.")

        self.display_textbox(text, choices=["YES", "NO"], process_fun=resp_process)


class SnakeNpc(PasswordNpc):
    def __init__(self, coords, name, walk_data):
        item = None
        super().__init__("Snake", self._password_correct, item,
                         "resources/NPCs/Snake_NPC_Blue.tmx",
                         coords, name, walk_data)

    @staticmethod
    def _password_correct(passwd):
        return passwd == "hunter1"
