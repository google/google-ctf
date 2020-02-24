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

gcloud container clusters delete ${CLUSTER_NAME}
gcloud compute routers delete "kctf-${CLUSTER_NAME}-nat-router" --region "${ZONE::-2}" --quiet

SUFFIX=$(echo "${PROJECT}-${CLUSTER_NAME}-${ZONE}" | sha1sum)
GSA_NAME="kctf-gcsfuse-${SUFFIX:0:16}"
GSA_EMAIL=$(gcloud iam service-accounts list --filter "name=${GSA_NAME}" --format 'get(email)' || true)
if [ -z "${GSA_EMAIL}" ]; then
  gcloud iam service-accounts delete "${GSA_EMAIL}"
fi
