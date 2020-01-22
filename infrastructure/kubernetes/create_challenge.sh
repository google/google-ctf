#!/bin/bash

set -Eeuo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
source "${DIR}/cluster_vars"

if [ $# != 1 ]; then
  echo 'missing path to challenge directory'
  exit 1
fi

CHALLENGE_DIR=$1

if [ -d "${CHALLENGE_DIR}" ]; then
  echo 'challenge alreadz exists'
  exit 1
fi

CHALLENGE_NAME=$(basename "${CHALLENGE_DIR}")

cp -r challenge-skeleton "${CHALLENGE_DIR}"

pushd "${CHALLENGE_DIR}"

sed -i "s/gctf-k8s/${PROJECT}/g" *.yaml
sed -i "s/challenge-skeleton/${CHALLENGE_NAME}/g" *.yaml

popd
