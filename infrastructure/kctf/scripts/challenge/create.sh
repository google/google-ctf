#!/bin/bash
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
set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_chal_dir

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR="${CHAL_DIR}/${CHALLENGE_NAME}"

if [ -d "${CHALLENGE_DIR}" ]; then
  echo 'challenge already exists'
  exit 1
fi

umask a+rx
cp -p -r "${CHAL_DIR}/kctf-conf/base/challenge-skeleton" "${CHALLENGE_DIR}"

pushd "${CHALLENGE_DIR}"

sed -i "s/challenge-skeleton/${CHALLENGE_NAME}/g" challenge/*/*.yaml healthcheck/*/*.yaml

popd
