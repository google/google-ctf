#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1

load_chal_dir

CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")

pushd "${CHALLENGE_DIR}"

source "${CHALLENGE_DIR}/chal.conf"

make -C "${CHALLENGE_DIR}" -j deploy

if [ "${PUBLIC}" = "true" ]; then
  echo '== CHALLENGE IS PUBLIC =='
  if [ "${KCTF_DONT_WAIT_LB}" != "true" ]; then
    echo 'Waiting for load balancer to come up, Ctrl-C if you don'"'"'t care'
    LB_IP=$($DIR/scripts/challenge/ip.sh "${CHALLENGE_NAME}")
    echo "Running at ${LB_IP}"
  fi
fi
