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

load_config

echo 'config loaded'
echo "CLUSTER_NAME: ${CLUSTER_NAME}"

for dir in ${CHAL_DIR}/*; do
  if [ ! -f "${dir}/chal.conf" ]; then
    continue
  fi
  source "${dir}/chal.conf"

  CHALLENGE_NAME=$(basename "${dir}")

  if [ ! "${DEPLOY}" = "true" ]; then
    echo
    echo "= Deleting all resources for ${CHALLENGE_NAME} ="
    echo
    make -C ${dir} stop
    continue
  fi

  echo
  echo "= Deploying challenge ${CHALLENGE_NAME} ="
  echo

  make -j -C "${dir}" start
done

echo
echo '= challenges deployed, waiting for load balancers ='
echo "ctrl+c if you don't care"
echo

for dir in ${CHAL_DIR}/*; do
  if [ ! -f "${dir}/chal.conf" ]; then
    continue
  fi
  source "${dir}/chal.conf"

  if [ ! "${DEPLOY}" = "true" ]; then
    continue
  fi

  if [ ! "${PUBLIC}" = "true" ]; then
    continue
  fi

  CHALLENGE_NAME=$(basename "${dir}")

  LB_IP=$(make -s -C "${dir}" ip)
  echo "${CHALLENGE_NAME}: ${LB_IP}"

done
