#!/usr/bin/python3
# Copyright 2021 Google LLC
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

with open("/proc/self/status", "rb") as s:
  status = s.readlines()

for line in status:
  if line.startswith(b"CapBnd:\t"):
    cap_inh = line.split(b"\t")[1]
    break
else:
  raise RuntimeError("Failed to find CapBnd in /proc/self/status")

capabilities = int(cap_inh, 16)
cap_ctr = 0
cap_list = []
while capabilities:
  if capabilities & 1:
    cap_list.append(f"-cap_{cap_ctr}")
  cap_ctr += 1
  capabilities //= 2

cap_list = ",".join(cap_list)
print(f"--inh-caps={cap_list}")
