#!/bin/bash
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

set -Eeuo pipefail

echo 'This script will update the chrome version.'
echo 'Make sure to install depot_tools first following https://chromium.googlesource.com/chromium/src/+/master/docs/linux/build_instructions.md'
echo 'And enable Goma!'
echo 'Btw, this will break the exploit, there are notes how to update it. Good luck :)'

if [ "$#" != 1 ]; then
  echo 'usage: ./update_chrome.sh version'
  echo 'e.g. ./update_chrome.sh tags/91.0.4472.101'
  exit 1
fi
VERSION=$1

# print all commands that are executed
set -x

if [ ! -d chromium_build ]; then
  mkdir chromium_build
  pushd chromium_build
  fetch --nohooks chromium
  cd src
  ./build/install-build-deps.sh
  gclient runhooks
else
  pushd chromium_build/src
  git stash || true
  git clean -fd || true
  pushd v8
  git stash || true
  git clean -fd || true
  popd
fi

git checkout "${VERSION}"
gclient runhooks
gclient sync

if [ ! -d out/Default ]; then
  gn gen out/Default
  echo -e 'is_debug=false\nuse_goma=true\nenable_nacl=false\nblink_symbol_level=0\nsymbol_level=1' > out/Default/args.gn
fi

git apply "../../sbx_bug.patch"

pushd v8
git apply "../../../v8_bug.patch"
popd

goma_ctl ensure_start

autoninja -C out/Default chrome

popd

if [ -d chromium ]; then
  rm -R chromium
fi
mkdir chromium
for f in chrome chrome_100_percent.pak chrome_200_percent.pak icudtl.dat product_logo_48.png resources.pak snapshot_blob.bin v8_context_snapshot.bin; do
  cp chromium_build/src/out/Default/$f chromium/
done

cp -R chromium_build/src/out/Default/swiftshader chromium/

mkdir chromium/mojo_bindings
cp chromium_build/src/out/Default/gen/mojo/public/js/mojo_bindings.js chromium/mojo_bindings/

pushd chromium_build/src/out/Default/gen
for f in $(find -name '*.mojom.js'); do
  DIR=../../../../../chromium/mojo_bindings/$(dirname "$f")
  mkdir -p "${DIR}" 2>/dev/null || true
  cp "$f" "${DIR}/"
done
popd

rm chromium.tar.xz || true
tar -cJf chromium.tar.xz chromium/

echo "Done! Don't forget to upload chromium.tar.xz to GCS, update the exploit, and update the VM image with make."
