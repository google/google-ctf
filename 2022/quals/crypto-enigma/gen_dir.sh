#!/bin/bash

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

set -e -x

original="$(find $1 -type f -iname "*.original.txt")"
base="${original/%.original.txt}"
plaintext="$base.plaintext.txt"
ciphertext="$base.ciphertext.txt"
fernet="$base.fernet.txt"
settings="$(dirname -- "$original")/settings"

echo $original $base $plaintext $ciphertext $fernet $settings

DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

$DIR/encode.py < "$original" > "$plaintext"
$DIR/bazel-bin/enigma/machine $(cat "$settings") < "$plaintext" > "$ciphertext"
$DIR/encrypt_modern.py encrypt $(cat "$settings") < "$original" > "$fernet"

# Test
$DIR/bazel-bin/enigma/machine $(cat "$settings") < "$ciphertext" > /tmp/decrypted_plaintext
cmp --silent "$plaintext" /tmp/decrypted_plaintext || echo "Decrypted plaintext differs"
$DIR/encrypt_modern.py decrypt $(cat "$settings") < "$fernet" > /tmp/decrypted_original
cmp --silent "$original" /tmp/decrypted_original || echo "Fernet-Decrypted original differs"
