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
  source "${dir}/chal.conf"

  CHALLENGE_NAME=$(basename "${dir}")

  if [ ! "${DEPLOY}" = "true" ]; then
    echo
    echo "= Deleting all resources for ${CHALLENGE_NAME} ="
    echo
    make -C ${dir} kill
    continue
  fi

  echo
  echo "= Deploying challenge ${CHALLENGE_NAME} ="
  echo

  make -j -C "${dir}" deploy
done

echo
echo '= challenges deployed, waiting for load balancers ='
echo "ctrl+c if you don't care"
echo

for dir in ${CHAL_DIR}/*; do
  if [ ! -f "${dir}/chal.conf" ]; then
    continue
  fi
  source "${dir}/chal.conf"

  if [ ! "${DEPLOY}" = "true" ]; then
    continue
  fi

  if [ ! "${PUBLIC}" = "true" ]; then
    continue
  fi

  CHALLENGE_NAME=$(basename "${dir}")

  LB_IP=$(make -s -C "${dir}" ip)
  echo "${CHALLENGE_NAME}: ${LB_IP}"

done
