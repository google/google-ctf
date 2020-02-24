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

if [ $# != 1 ]; then
    echo 'missing path to config'
    exit 1
fi

CONFIG_FILE="$(realpath -L $1)"
source ${CONFIG_FILE}

# sanity check
if [ -z ${CLUSTER_NAME} ]; then
    echo 'error: CLUSTER_NAME not in config. Valid config file?'
    exit 1
fi
if [ -z ${PROJECT} ]; then
    echo 'error: PROJECT not in config. Valid config file?'
    exit 1
fi

echo "loaded config for ${CLUSTER_NAME} in ${PROJECT}"

mkdir -p "${HOME}/.config/kctf"
ln -fs "${CONFIG_FILE}" "${HOME}/.config/kctf/cluster.conf"

create_gcloud_config

# there might be an existing cluster, try to get the creds
get_cluster_creds 2>/dev/null || true
