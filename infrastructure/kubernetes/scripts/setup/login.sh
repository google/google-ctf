#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."

if [ ! -f ~/.config/kctf/cluster.conf ]; then
    echo 'cluster config not found, please create or load it first'
    exit 1
fi
source ~/.config/kctf/cluster.conf

if [ ! -x $(which kubectl) ]; then
  gcloud components install kubectl
fi
gcloud container clusters get-credentials ${CLUSTER_NAME}
gcloud auth configure-docker
