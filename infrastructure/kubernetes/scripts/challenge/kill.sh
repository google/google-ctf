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

kubectl delete "secret/${CHALLENGE_NAME}-secrets" || echo 'deleting secret failed'
kubectl delete "configMap/${CHALLENGE_NAME}-config" || echo 'deleting pow failed'

kubectl delete -f "${CHALLENGE_DIR}/k8s/containers.yaml" || echo 'deleting containers failed'
kubectl delete -f "${CHALLENGE_DIR}/k8s/autoscaling.yaml" || echo 'deleting autoscaling failed'
kubectl delete -f "${CHALLENGE_DIR}/k8s/network.yaml" || echo 'deleting load balancer failed'
