#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

if [ ! -x $(which kubectl) ]; then
  gcloud components install kubectl
fi
gcloud container clusters get-credentials ${CLUSTER_NAME}
gcloud auth configure-docker
