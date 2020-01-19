#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source $DIR/config/CLUSTER_VARS

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

BOT_DIR="${DIR}/util/xss-bot"

pushd "${BOT_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/xss-bot" .
docker push "eu.gcr.io/${PROJECT}/xss-bot"

popd

if [ $# != 1 ]; then
    exit 0
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR=$(readlink -f "${DIR}/challenges/${CHALLENGE_NAME}")

pushd "${CHALLENGE_DIR}"

kubectl create secret generic "${CHALLENGE_NAME}-cookie" --from-file="cookie"
kubectl create -f "challenge.yaml"
kubectl create -f "autoscaling.yaml"

popd
