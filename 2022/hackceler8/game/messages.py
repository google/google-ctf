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

import network
import serialize
import serialization_pb2
import game as game_mod
import persistent_state


# This is used to tell the client its shared base value.
initialize_base_value = network.register("initialize_base_value", int)
tick = network.register("tick", network.JSON)
stop_diff = network.register("stop_diff", serialize.SerializableTuple)
stop = network.register("stop", str)
request_save = network.register("request_save", bytes)
request_save_response = network.register("request_save_response", bytes)
request_load = network.register("request_load", bytes)
request_load_response = network.register("request_load_response", bytes)
check_valid = network.register("check_valid", serialization_pb2.SerializedPackage)
is_valid = network.register("is_valid", type(None))

request_save_persistent_state = network.register("request_save_persistent_state", type(None))
request_save_persistent_state_response = network.register("request_save_persistent_state_response", str)
request_load_persistent_state = network.register("request_load_persistent_state", type(None))
request_load_persistent_state_response = network.register("request_load_persistent_state_response", persistent_state.PersistentState)

use_item = network.register("use_item", int)
open_chat = network.register("open_chat", bytes)
exit_chat = network.register("exit_chat", bytes)
send_chat = network.register("send_chat", str)
send_chat_response = network.register("send_chat_response", str)
