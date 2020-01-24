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

if [ -d "${CHALLENGE_DIR}" ]; then
  echo 'challenge already exists'
  exit 1
fi

cp -r "${DIR}/util/challenge-skeleton" "${CHALLENGE_DIR}"

pushd "${CHALLENGE_DIR}"

sed -i "s/gctf-k8s/${PROJECT}/g" config/*.yaml Dockerfile
sed -i "s/challenge-skeleton/${CHALLENGE_NAME}/g" config/*.yaml

popd
