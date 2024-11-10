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

import enum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from moderngl_window.context.base import BaseKeys


class Keys(enum.Enum):
    """
    Graphics backend independent keyboard handling.

    This class is somewhat magical. It mostly behaves like a regular Python Enum (with its singleton instances),
    but we add extra functionality to fill in the UI keys at runtime.
    """
    __rev_serialized: dict[str, 'Keys'] = {}
    __rev_ui: dict[int, 'Keys'] = {}
    __ui_key_cls: Optional['BaseKeys'] = None

    def __init__(self, serkey: str, uikey: str):
        cls = self.__class__
        self.serialized = serkey
        self.ui = uikey
        if serkey is not None:
            assert serkey not in cls.__rev_serialized, serkey
            cls.__rev_serialized[serkey] = self

    @classmethod
    def update_ui_keys(cls, keyclass: 'BaseKeys'):
        cls.__ui_key_cls = keyclass
        for i in cls:
            if not i.ui:
                continue
            i.ui = getattr(keyclass, i.ui)
            assert i.ui not in cls.__rev_ui
            cls.__rev_ui[i.ui] = i

    @classmethod
    def from_serialized(cls, k: str) -> Optional['Keys']:
        return cls.__rev_serialized.get(k)

    @classmethod
    def from_ui(cls, k: int) -> Optional['Keys']:
        return cls.__rev_ui.get(k)

    # https://docs.python.org/3/howto/enum.html#orderedenum
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    LSHIFT     = ('L',  'LEFT_SHIFT')
    LCTRL      = (None, None)
    ESCAPE     = ('E',  'ESCAPE')
    UP         = (None, 'UP')
    DOWN       = (None, 'DOWN')
    RIGHT      = (None, 'RIGHT')
    ENTER      = ('N',  'ENTER')
    BACKSPACE  = (None, 'BACKSPACE')
    SPACE      = (' ',  'SPACE')
    A          = ('a',  'A')
    B          = ('b',  'B')
    C          = ('c',  'C')
    D          = ('d',  'D')
    E          = ('e',  'E')
    F          = ('f',  'F')
    G          = ('g',  'G')
    H          = ('h',  'H')
    I          = ('i',  'I')
    J          = ('j',  'J')
    K          = ('k',  'K')
    L          = ('l',  'L')
    M          = ('m',  'M')
    N          = ('n',  'N')
    O          = ('o',  'O')
    P          = ('p',  'P')
    Q          = ('q',  'Q')
    R          = ('r',  'R')
    S          = ('s',  'S')
    T          = ('t',  'T')
    U          = ('u',  'U')
    V          = ('v',  'V')
    W          = ('w',  'W')
    X          = ('x',  'X')
    Y          = ('y',  'Y')
    Z          = ('z',  'Z')
