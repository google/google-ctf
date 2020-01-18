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

while : ; do
  LB_IP=$(kubectl get services | grep "${CHALLENGE_NAME}" | awk '{print $4}')
  if [ "${LB_IP}" != "<pending>" ]; then
      echo "${LB_IP}"
      break;
  fi
  sleep 3
done
