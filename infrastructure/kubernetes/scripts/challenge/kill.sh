#!/bin/bash

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

kubectl delete "secret/${CHALLENGE_NAME}-flag"
kubectl delete "configMap/${CHALLENGE_NAME}-pow" || true

kubectl delete -f "${CHALLENGE_DIR}/config/containers.yaml"
kubectl delete -f "${CHALLENGE_DIR}/config/autoscaling.yaml"
kubectl delete -f "${CHALLENGE_DIR}/config/network.yaml" || echo 'ignoring error trying to delete the load balancer'
