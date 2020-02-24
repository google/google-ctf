#!/bin/bash

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
