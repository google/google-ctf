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
import validation
import serialization_pb2
import context_aware_serialization

class SaveBlob(serialize.SerializableObject):
    def __init__(self):
        self.games = {}
        self.current_game = ""

def make_blob(games, game):
    blob = SaveBlob()
    for map_name, named_game in games.items():
        blob.games[map_name] = validation.server_state_binary_serialized(named_game)
        if game == named_game:
            print(f"Setting current game to {map_name}")
            blob.current_game = map_name
    if blob.current_game == "":
        raise RuntimeError("Expected current game to appear on dict of games.")

    msg = validation.server_state_binary_serialized(blob)

    return msg

def load_blob(blob, existing_games):
    blob_proto = serialization_pb2.SerializedPackage.FromString(blob)
    blob = serialize.Deserialize(blob_proto)
    games = {}

    for map_name, named_game in blob.games.items():
        save = serialization_pb2.SerializedPackage.FromString(named_game)
        c = context_aware_serialization.Context(existing_games[map_name].tmx_map)
        games[map_name] = serialize.Deserialize(save, c)

    game = games[blob.current_game]
    return (games, game)