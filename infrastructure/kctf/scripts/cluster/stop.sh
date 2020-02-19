#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

gcloud container clusters delete ${CLUSTER_NAME}
gcloud compute routers delete kctf-${CLUSTER_NAME}-nat-router --region ${ZONE::-2}
