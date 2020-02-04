#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

echo "Status of cluster ${CLUSTER_NAME} in ${ZONE}"
echo
gcloud container clusters describe "${CLUSTER_NAME}" --zone "${ZONE}" --format='value(status)'
