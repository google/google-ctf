#!/bin/bash
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

# needs depot_tools in the path
# git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
# export PATH="$PATH:/path/to/depot_tools"

# https://chromium.googlesource.com/chromium/src/+/master/docs/linux_build_instructions.md
fetch --nohooks chromium
cd src
build/install-build-deps.sh
gclient runhooks

# https://www.chromium.org/developers/how-tos/get-the-code/working-with-release-branches
git fetch --tags
git checkout tags/70.0.3538.9
gclient sync

gn gen out/Default
echo << EOF
Please set the following args:
> use_jumbo_build=true
> enable_nacl=false
> remove_webcore_debug_symbols=true
> use_goma = true # for googlers
> is_debug = false
EOF
gn args out/Default

git apply ../attachments/nosandbox.patch
pushd v8
git apply ../attachments/addition-reducer.patch
popd

autoninja -C out/Default chrome
