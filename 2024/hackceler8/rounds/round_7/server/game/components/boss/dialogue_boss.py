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
            self.game.display_textbox(from_server=True, response_callbacks={"Imposssssible, that's correct": self._start_destruct})

    def secret_server_dialogue(self):
        # TODO BEFORE RELEASING TO PLAYERS: Remove block start
        secret = "B1g 3xPl0s1oN!"
        def add_secrets(resp: str):
            if resp == "I'm good thanks":
                self.game.display_textbox("Farewell")
                return
            self._show_secrets()
        def guess(resp: str):
            if resp == secret:
                self.game.display_textbox("Imposssssible, that's correct!\n", process_fun=self._start_destruct)
            else:
                txt = "Incorrect!\nAs a consolation you can add your own ssssssecrets to my storage. It's all stored in one buffer to make it extra sssssecure!"
                self.game.display_textbox(txt, choices=["I'll check out the secrets", "I'm good thanks"], process_fun=add_secrets)

        def maybe_guess(resp: str):
            if resp == "I know the secret spell!":
                self.game.display_textbox("Let me hear it then!", free_text=True, process_fun=guess)
            else:
                self.game.display_textbox("Farewell")

        self._setup_buf(secret)
        self.game.display_textbox("Greetingssss, mortal!\nYou shall not passss unless you can utter the secret sssspell.", choices=["I know the secret spell!", "Okay, bye"], process_fun=maybe_guess)
        return
        # TODO BEFORE RELEASING TO PLAYERS: Remove block end
        self.game.display_textbox("Boss battle only available on the sssserver.")

    def _start_destruct(self, text):
        text = "I've been defeated! Victory is yours young canine."
        self.sprite.set_animation("die")
        self.game.display_textbox(text, process_fun=self.destruct)
    # TODO BEFORE RELEASING TO PLAYERS: Remove block start
    def _setup_buf(self, secret):
        self.buf = b""
        self._add_to_buf(b"UNUSED", 10)
        # Owner strings
        owner_player_ptr = self._add_to_buf(b"Domino", 16)
        owner_boss_ptr = self._add_to_buf(b"Snek lady", 16)
        # Boss secret strings
        boss_secrets = [[self._add_to_buf(b"Favourite drink", 16), self._add_to_buf(b"Margarita snake", 16)]]
        boss_secrets += [[self._add_to_buf(b"Biggest fear", 16), self._add_to_buf(b"Heights", 16)]]
        boss_secrets += [[self._add_to_buf(b"The magic spell", 16), self._add_to_buf(bytes(secret, "utf-8"), 16)]]
        # Player secret strings (empty initially)
        player_secrets = [[self._add_to_buf(b"", 16), self._add_to_buf(b"", 16)]]
        player_secrets += [[self._add_to_buf(b"", 16), self._add_to_buf(b"", 16)]]
        player_secrets += [[self._add_to_buf(b"", 16), self._add_to_buf(b"", 16)]]
        # Secret structs
        self.secret_ptrs = []
        for s in player_secrets:
            self.secret_ptrs.append(
                self._add_secret_struct(s[0], s[1], owner_player_ptr))
        for s in boss_secrets:
            self.secret_ptrs.append(
                self._add_secret_struct(s[0], s[1], owner_boss_ptr))
        # Padding
        self.buf += b"\0"*(256-len(self.buf))
        # print("secret_ptrs:", self.secret_ptrs)
        # print(self.buf)
        # for s in self.secret_ptrs:
        #     print("loc", s)
        #     print("Title", self.buf[s], self._read_str(self.buf[s]))
        #     print("Content", self.buf[s+1], self._read_str(self.buf[s+1]))
        #     print("Owner", self.buf[s+2], self._read_str(self.buf[s+2]))
        #     print("---")
        assert len(self.buf) == 256

    def _add_to_buf(self, txt, pad_to=0) -> int:
        ptr = len(self.buf)
        self.buf += txt
        if pad_to > 0:
            assert len(txt) < pad_to
            self.buf += b"\0"*(pad_to-len(txt))
        return ptr

    def _write_to_buf(self, txt, ptr):
        for s in txt:
            if ptr >= len(self.buf):
                break
            self.buf = self.buf[:ptr] + ord(s).to_bytes() + self.buf[ptr+1:]
            ptr += 1

    def _add_secret_struct(self, title, content, owner) -> int:
        assert title < 256
        assert content < 256
        assert owner < 256
        ptr = len(self.buf)
        self.buf += title.to_bytes()+content.to_bytes()+owner.to_bytes()
        return ptr

    def _read_str(self, ptr) -> str:
        if ptr < 0 or ptr >= len(self.buf):
            return "[OOB]"
        if self.buf[ptr] == 0:
            return "[Empty]"
        ret = ""
        while ptr < len(self.buf) and self.buf[ptr] != 0:
            ret += chr(self.buf[ptr])
            ptr += 1
        return ret

    def _restart(self, text):
        def view(resp):
            if resp == "No":
                self.game.display_textbox("Farewell")
                return
            self._show_secrets()
        self.game.display_textbox(text + "\nDo you want to view another sssssecret?", choices=["Yes", "No"], process_fun=view)

    def _show_secrets(self):
        self.selection = 0
        def write_content(resp):
            self._write_to_buf(resp, self.buf[self.selection+1])
            self._restart("Wrote to the buffer!")
        def write_title(resp):
            self._write_to_buf(resp, self.buf[self.selection])
            self.game.display_textbox("What's the new content?", free_text=True, process_fun=write_content)
        def view(resp):
            if resp == "Read":
                self._restart("Here's your ssssssecret \"%s\":\n%s" % (self._read_str(self.buf[self.selection]), self._read_str(self.buf[self.selection+1])))
                return
            self.game.display_textbox("What's the new title?", free_text=True, process_fun=write_title)

        def select(resp):
            try:
                i = int(resp)
            except:
                self._restart("Integer pls")
                return
            i -= 1
            if i < 0 or i >= len(self.secret_ptrs):
                self._restart("Within the range pls")
                return
            self.selection = self.secret_ptrs[i]
            if self._read_str(self.buf[self.selection+2]) != "Domino":
                self._restart("That's not your sssssecret, I can't show you that!")
                return
            self.game.display_textbox("Would you like to read the ssssssecret or rewrite it?", choices=["Read", "Write"], process_fun=view)
        txt = "Here are the available sssssecrets:\n"
        for i in range(len(self.secret_ptrs)):
            s = self.secret_ptrs[i]
            txt += "%d: %s (owner: %s)\n" % (i+1, self._read_str(self.buf[s]), self._read_str(self.buf[s+2]))
        txt += "Which sssssecret do you want to see? Input the index."
        self.game.display_textbox(txt, free_text=True, process_fun=select)

    # TODO BEFORE RELEASING TO PLAYERS: Remove block end

    def tick(self):
        super().tick()
        if self.destructing or self.dead:
            return
        self.sprite.set_flipped(self.game.player.x < self.x)
