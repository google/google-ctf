#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1

while : ; do
  LB_IP=$(kubectl get services | grep "${CHALLENGE_NAME}" | awk '{print $4}')
  if [ "${LB_IP}" != "<pending>" ]; then
      echo "${LB_IP}"
      break;
  fi
  sleep 3
done
