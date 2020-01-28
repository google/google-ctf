#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

echo 'config loaded'
echo "CLUSTER_NAME: ${CLUSTER_NAME}"

for dir in ${CHAL_DIR}/*; do
  if [ ! -f "${dir}/chal.conf" ]; then
    continue
  fi

  CHALLENGE_NAME=$(basename "${dir}")
  CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")
  source "${CHALLENGE_DIR}/chal.conf"

  if [ ! "${DEPLOY}" = "true" ]; then
    echo
    echo "= Deleting all resources for ${CHALLENGE_NAME} ="
    echo
    ${DIR}/scripts/challenge/kill.sh "${CHALLENGE_NAME}"
    continue
  fi

  echo
  echo "= Deploying challenge ${CHALLENGE_NAME} ="
  echo
  ${DIR}/scripts/challenge/deploy.sh "${CHALLENGE_NAME}"
done
