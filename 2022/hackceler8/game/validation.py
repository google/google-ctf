# Copyright 2022 Google LLC
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

import serialize
import struct
import serialization_pb2
import environ

from typing import Optional

from hashlib import blake2b
from hmac import compare_digest
import difflib

AUTH_SIZE = 32


def Validate(client_game_state, server_game) -> Optional[tuple[str, str]]:
    """
    Validate the client game state.
    This is used to make sure that the client game state is equal to the server
    game state.
    """
    server_game_state = serialize_server_state(server_game)
    server_str = serialize.stringify_state(server_game_state)
    client_str = serialize.stringify_state(client_game_state)

    if True and server_str != client_str:
        with open("/tmp/server.txt", "w") as f:
            f.write(server_str)
        with open("/tmp/client.txt", "w") as f:
            f.write(client_str)
        with open("/tmp/diff.html", "w") as f:
            f.write(difflib.HtmlDiff().make_file(server_str.split("\n"), client_str.split("\n"),
                                                 fromdesc="Server", todesc="Client"))

    if server_str == client_str:
        return None
    return (server_str, client_str)

def serialize_server_state(server_game):
    # serialize this game state using the shared value.
    server_game_state_serialized = serialize.Serialize(server_game)
    return server_game_state_serialized
    server_game_state = server_game_state_serialized.SerializeToString() #bytes(repr(server_game_state_serialized), "ascii")

    return server_game_state

def server_state_binary_serialized(server_game) -> bytes:
    server_game_state_serialized = serialize.Serialize(server_game)
    return server_game_state_serialized.SerializeToString()

@environ.server_only
def get_signature(state: bytes, secret_key: bytes) -> bytes:
    """
    We can sign a game state and provide the signature given a secret key.
    """
    h = blake2b(digest_size=AUTH_SIZE, key=secret_key)
    h.update(state)
    return h.digest()

@environ.server_only
def verify_signature(state: bytes, secret_key: bytes) -> tuple[bool, bytes]:
    """
    We expect the save state to have its signature at the end.
    We then generate a signature with out secret key for the client's provided
    state and then compare it with the signature that the client provided.
    """
    good_signature = get_signature(state[:-AUTH_SIZE], secret_key)
    valid = compare_digest(good_signature, state[-AUTH_SIZE:])

    # remove the signature from the state
    state = state[:-AUTH_SIZE]

    return valid, state
