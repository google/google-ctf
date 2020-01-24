#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source $DIR/config/CLUSTER_VARS

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR=$(readlink -f "${DIR}/challenges/${CHALLENGE_NAME}")

pushd "${CHALLENGE_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}" .
docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"

popd
