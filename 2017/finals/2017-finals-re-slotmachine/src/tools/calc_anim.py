#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Fancy animation!
# For now, use 15 chars as a period
from math import sin, pi
# N = 15
N = 35
amplitude = 10

values = map(int, [amplitude * sin(2 * pi * (float(i) / float(N))) for i in range(N)])

print("constexpr int8_t sin_offsets[] = {{{}}};".format(", ".join([str(v) for v in values])))