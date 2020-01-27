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

kubectl delete "secret/${CHALLENGE_NAME}-flag" || echo 'deleting secret failed'
kubectl delete "configMap/${CHALLENGE_NAME}-pow" || echo 'deleting pow failed'

kubectl delete -f "${CHALLENGE_DIR}/config/containers.yaml" || echo 'deleting containers failed'
kubectl delete -f "${CHALLENGE_DIR}/config/autoscaling.yaml" || echo 'deleting autoscaling failed'
kubectl delete -f "${CHALLENGE_DIR}/config/network.yaml" || echo 'deleting load balancer failed'
