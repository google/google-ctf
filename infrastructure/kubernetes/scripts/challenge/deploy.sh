#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."

if [ ! -f ~/.config/kctf/cluster.conf ]; then
    echo 'cluster config not found, please create or load it first'
    exit 1
fi
source ~/.config/kctf/cluster.conf

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")

pushd "${CHALLENGE_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}" .
docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"
kubectl create secret generic "${CHALLENGE_NAME}-flag" --from-file="secrets/flag"

pushd config
kubectl create -f "containers.yaml"
kubectl create -f "autoscaling.yaml"
if [ -f pow.yaml ]; then
  kubectl create -f "pow.yaml"
fi

popd

popd
