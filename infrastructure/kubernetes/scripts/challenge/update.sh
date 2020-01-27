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
CLUSTER_CONF_DIR="${CHAL_DIR}/kctf-conf/${PROJECT}_${ZONE}_${CLUSTER_NAME}/${CHALLENGE_NAME}"

pushd "${CHALLENGE_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}" .
docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"

pushd config

if [ -f pow.yaml ]; then
  kubectl apply -f "pow.yaml"
fi

kubectl delete -f "containers.yaml"
# This will use the kustomization.yaml to spawn the containers.yaml
kubectl create -k "${CLUSTER_CONF_DIR}"

popd

popd
