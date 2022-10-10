#!/usr/bin/python3

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

# Author: Ian Eldred Pudney

"""Encodes text in the style it would be written prior to Enigma-ing."""

import sys

text = sys.stdin.read()
text = text.upper()

# Letter representation
text = text.replace('Ä', 'AE')
text = text.replace('Ö', 'OE')
text = text.replace('Ü', 'UE')
text = text.replace('ẞ', 'SS')
text = text.replace('ß', 'SS')

# Punctuation representation
text = text.replace('.', 'X')
text = text.replace('!', 'X')
text = text.replace("?", 'UD')

text = text.replace(':', 'XX')
text = text.replace(',', 'Y')

text = text.replace('--', 'YY')
text = text.replace('-', 'YY')
text = text.replace('/', 'YY')
text = text.replace('\\', 'YY')

text = text.replace('"', 'J')
text = text.replace("'", 'J')
text = text.replace("„", 'J')
text = text.replace("“", 'J')
text = text.replace("»", 'J')
text = text.replace("«", 'J')

text = text.replace("(", 'KK')
text = text.replace(")", 'KK')
text = text.replace("[", 'KK')
text = text.replace("]", 'KK')
text = text.replace("{", 'KK')
text = text.replace("}", 'KK')

# Strip anything that's left
text = "".join([c if (ord(c) >= ord('A') and ord(c) <= ord('Z')) else "" for c in text])

# Break into chunks and lines
text = "".join(text[i:i+4] + " " for i in range(0, len(text), 4))
text = "".join(text[i:i+50] + "\n" for i in range(0, len(text), 50))
text = text.replace(" \n", "\n")
text = text.strip()

sys.stdout.write(text)
