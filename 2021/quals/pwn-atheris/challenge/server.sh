#!/bin/bash

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Ian Eldred Pudney

echo "Please send a 4-byte little-endian integer specifying the size of a zip file, followed by said zip file."
set -e -x

cd "$(dirname "${BASH_SOURCE[0]}")"
rm -rf unzipped/*

# Receive a zip file from stdin.
tmpdir="$(mktemp -d)"
./recv_zip "${tmpdir}/zipfile.zip"

# Autorun it.
python3 ./autorunner.py "${tmpdir}/zipfile.zip" "unzipped/"

