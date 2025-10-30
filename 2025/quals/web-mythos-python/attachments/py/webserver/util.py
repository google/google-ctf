# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import random
import string
import os


def copy(src, dst):
    for k, v in src.items():
        if hasattr(dst, "__getitem__"):
            if dst.get(k) and type(v) == dict:
                copy(v, dst.get(k))
            else:
                dst[k] = v
        elif hasattr(dst, k) and type(v) == dict:
            copy(v, getattr(dst, k))
        else:
            setattr(dst, k, v)


def rand_name(length):
    characters = string.ascii_letters + string.digits
    return "".join(random.choice(characters) for _ in range(length))


GAME_URL = os.environ.get("GAME_URL") or "http://localhost:5000/"


def game_url(path="game"):
    return GAME_URL + path
