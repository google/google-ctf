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

import os
import sys
from datetime import datetime

import settings
settings.environ = 'server'
import environ
import messages
import serialization_pb2
import serialize


with open(sys.argv[1], 'rb') as f:
    data = f.read()

save = serialization_pb2.SerializedPackage.FromString(data)
st = serialize.Deserialize(save, None)
for flag, ts in st._state_fields['obtained_flags'].items():
    print(f'{flag} at {datetime.fromtimestamp(ts)}')

print(f'game complete: {datetime.fromtimestamp(st._state_fields["game_complete"])}')
