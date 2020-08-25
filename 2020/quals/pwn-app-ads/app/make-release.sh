#!/bin/bash
# Copyright 2020 Google LLC
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

# Generates the challenge APK file.

set -e

tmp=$(mktemp -d)

# First clean everything, incremental builds do not pick up changes to the
# ads-impl.apk...
./gradlew \
  :ads-api:clean \
  :ads-common:clean \
  :ads-impl:apk:clean \
  :ads-impl:clean \
  :app:clean

./gradlew :app:assembleRelease

zipalign -v -p 4 \
  "app/build/outputs/apk/release/app-release-unsigned.apk" \
  "$tmp/app-unsigned-aligned.apk"

apksigner sign \
  --ks release-key.jks \
  --ks-pass pass:password \
  --key-pass pass:password \
  --out ../attachments/app-release.apk \
  "$tmp/app-unsigned-aligned.apk"

rm -Rf "$tmp"
