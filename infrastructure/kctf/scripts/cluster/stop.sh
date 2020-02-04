#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

gcloud config set project ${PROJECT}
gcloud config set compute/zone ${ZONE}

gcloud container clusters delete ${CLUSTER_NAME}
