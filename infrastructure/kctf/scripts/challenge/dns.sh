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

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")

if [ ! -z "${DOMAIN_NAME}" ]
then
    LB_IP=$(make -s -C "${CHALLENGE_DIR}" ip)
    gcloud dns record-sets transaction start --zone="${CLUSTER_NAME}-dns-zone"
    gcloud dns record-sets transaction add --zone="${CLUSTER_NAME}-dns-zone" --ttl 30 --name "${CHALLENGE_NAME}.${DOMAIN_NAME}." --type A "${LB_IP}"
    gcloud dns record-sets transaction execute --zone="${CLUSTER_NAME}-dns-zone"
else
    echo "DOMAIN_NAME not defined. Run ./scripts/setup/config.sh"
fi
