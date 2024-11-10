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

import os
import logging
from game.components.boss.boss import Boss
from game.engine import hitbox


class DialogueBoss(Boss):

    def __init__(self, coords):
        super().__init__(coords, name="dialogue_boss", tileset_path="resources/villain/snake_lady.h8t")
        self.name = "dialogue_boss"
        rect = hitbox.Rectangle(coords.x - 60, coords.x + 60, coords.y - 90, coords.y + 90)
        self.update_hitbox(rect)


    def _chat(self):
        if self.game.is_server or self.game.net is None:
            self.secret_server_dialogue()
        else:
            self.game.display_textbox(from_server=True, response_callbacks={"Imposssssible, " + "that's correct": self._start_destruct})

    def secret_server_dialogue(self):
        # TODO BEFORE RELEASING TO PLAYERS: Remove block start
        secret = "muy bueno pero prefiero los churros"
        r = [
            "Albondigas", "Fideua", "Gazpacho", "Leche Frita",
            "Patatas Bravas", "Pimientos de Padron",
        ]
        def pick(resp: str):
            self.game.display_textbox(self.get_recipe(resp))

        def guess(resp: str):
            if resp.lower() == secret:
                self.game.display_textbox("Imposssssible, " + "that's correct!\n", process_fun=self._start_destruct)
            else:
                text = "Incorrect! As a consolation I'll tell you one of my grandmother'sssss recipes. Which one do you want to know? Here are the options:\n"
                text += ", ".join(r)
                self.game.display_textbox(text, process_fun=pick, free_text=True)

        def maybe_guess(resp: str):
            if resp == "I know the secret spell!":
                self.game.display_textbox("Let me hear it then!", free_text=True, process_fun=guess)
            else:
                self.game.display_textbox("Farewell")

        self.game.display_textbox("Greetingssss, mortal!\nYou shall not passss unless you can utter the secret sssspell.", choices=["I know the secret spell!", "Okay, bye"], process_fun=maybe_guess)
        return
        # TODO BEFORE RELEASING TO PLAYERS: Remove block end
        self.game.display_textbox("Boss battle only available on the sssserver.")

    # TODO BEFORE RELEASING TO PLAYERS: Remove block start
    def get_recipe(self, name):
        cwd = os.getcwd().removesuffix("/")
        filename = name.lower().replace(" ", "_")+".txt"
        filename = os.path.join(cwd, "game", "components", "boss", "recipes", filename)
        # No hacking!
        if filename.find(".py") != -1:
            filename = filename[:filename.find(".py")]
        filename = filename.replace("../", "")
        filename = os.path.abspath(filename)
        # TODO BEFORE RELEASING TO PLAYERS: Actual remove block start
        if not filename.startswith(cwd): # Poor man's sandbox
            return "Permission error"
        fro = os.path.join(cwd, "game/components/boss/fake-game")
        to = "/home/user/hx8"
        # Path traversal should happen in the fake game dir where we have most
        # redactions applied.
        filename = os.path.join(fro, filename.removeprefix(cwd+"/"))
        # TODO BEFORE RELEASING TO PLAYERS: Actual remove block end
        try:
            with open(filename, 'r') as f:
                return f.read()
        except Exception as e:
            txt = str(e)
            # TODO BEFORE RELEASING TO PLAYERS: Actual remove block start
            txt = txt.replace(fro, to)
            # TODO BEFORE RELEASING TO PLAYERS: Actual remove block end
            return txt

    # TODO BEFORE RELEASING TO PLAYERS: Remove block end
    def _start_destruct(self, text):
        text = "I've been defeated! Victory is yours young canine."
        self.sprite.set_animation("die")
        self.game.display_textbox(text, process_fun=self.destruct)

    def tick(self):
        super().tick()
        if self.destructing or self.dead:
            return
        self.sprite.set_flipped(self.game.player.x < self.x)

# TODO BEFORE RELEASING TO PLAYERS: Remove block start
# TODO BEFORE RELEASING TO PLAYERS: Actual remove block start
# Generate a fake game directory for the path traversal.
# This contains the game with the regular client-side redactions except that
# dialogue_boss.py has the code for the server-side dialogue in it.
def generate_fake_game():
    import subprocess
    try:
        real_time = os.path.getmtime("game/components/boss/dialogue_boss.py")
        fake_time = os.path.getmtime("game/components/boss/fake-game")
        if fake_time >= real_time: # Already generated.
            return
        # Remove old dir before creating a new one.
        subprocess.run(["rm", "-r", "game/components/boss/fake-game"])
    except:
        pass
    logging.info("Generating fake game directory for dialogue boss battle")
    # Copy game elements into a fake game dir.
    subprocess.run(["mkdir", "fake-game"])
    subprocess.run(["cp", "-r", "dev", "game", "README.md", "client.py",
                    "requirements.txt", "server.py", "resources", "fake-game"])
    subprocess.run(["mv", "fake-game", "game/components/boss"])
    # Apply redactions to the fake game dir.
    subprocess.check_call(['python3', 'redact_for_release.py'], cwd="game/components/boss/fake-game/dev")

# TODO BEFORE RELEASING TO PLAYERS: Actual remove block end
# TODO BEFORE RELEASING TO PLAYERS: Remove block end
