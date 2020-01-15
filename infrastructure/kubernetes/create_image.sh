#!/bin/bash

set -Eeuo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
source "${DIR}/cluster_vars"

if [ $# != 1 ]; then
  echo 'missing path to challenge directory'
  exit 1
fi

CHALLENGE_DIR=$1
CHALLENGE_NAME=$(basename "${CHALLENGE_DIR}")

pushd "${CHALLENGE_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}" .
docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"

popd
