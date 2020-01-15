#!/bin/bash

set -Eeuo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
source "${DIR}/cluster_vars"

BOT_DIR="${DIR}/xss-bot"

pushd "${BOT_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/xss-bot" .
docker push "eu.gcr.io/${PROJECT}/xss-bot"

popd

if [ $# != 1 ]; then
  exit 0
fi

CHALLENGE_DIR=$1
CHALLENGE_NAME=$(basename "${CHALLENGE_DIR}")

pushd "${CHALLENGE_DIR}"

kubectl create secret generic "${CHALLENGE_NAME}-cookie" --from-file="cookie"
kubectl create -f "challenge.yaml"
kubectl create -f "autoscaling.yaml"

popd
