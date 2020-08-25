#!/bin/bash
#
#Copyright 2020 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

set -Eeuo pipefail

echo 'This script will update the chrome version. It should be run before the CTF using the latest stable version. (e.g. check chrome://version on your desktop)'
echo 'Make sure to install depot_tools first following https://chromium.googlesource.com/chromium/src/+/master/docs/linux/build_instructions.md'
echo 'And enable GOMA!'
echo 'Btw, this will break the exploit, there are notes how to update it. Good luck :)'

if [ "$#" != 1 ]; then
  echo 'usage: ./update_chrome.sh version'
  echo 'e.g. ./update_chrome.sh 81.0.4044.141'
  exit 1
fi
VERSION=$1

echo "tags/${VERSION}" > attachments/chrome_version.txt

# print all commands that are executed
set -x

if [ ! -d chromium ]; then
  mkdir chromium
  pushd chromium
  fetch --nohooks chromium
  cd src
  ./build/install-build-deps.sh
  gclient runhooks
else
  pushd chromium/src
  git stash || true
  git clean -f || true
fi

git checkout "tags/$VERSION"
gclient sync

if [ ! -d out/Default ]; then
  gn gen out/Default
  echo -e 'is_debug=false\nuse_goma=true\nenable_nacl=false' > out/Default/args.gn
fi

for PATCH in ../../attachments/*.patch; do
  patch -p1 < "${PATCH}"
done

autoninja -C out/Default chrome

popd

if [ -d attachments/chrome ]; then
  rm -R attachments/chrome
fi
mkdir attachments/chrome
for f in chrome chrome_100_percent.pak chrome_200_percent.pak icudtl.dat product_logo_48.png resources.pak snapshot_blob.bin v8_context_snapshot.bin xdg-mime xdg-settings; do
  cp chromium/src/out/Default/$f attachments/chrome/
done
for f in locales MEIPreload swiftshader; do
  cp -R chromium/src/out/Default/$f attachments/chrome/
done

if [ -d attachments/bindings ]; then
  rm -R attachments/bindings
fi
mkdir attachments/bindings
cp chromium/src/out/Default/gen/mojo/public/js/mojo_bindings.js attachments/bindings/

pushd chromium/src/out/Default/gen
for f in $(find -name '*.mojom.js'); do
  DIR=../../../../../attachments/bindings/$(dirname "$f")
  mkdir -p "${DIR}" 2>/dev/null || true
  cp "$f" "${DIR}/"
done
popd

pushd attachments
patch -p1 < mojo_bindings.diff
popd
