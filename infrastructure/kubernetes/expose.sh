#!/bin/bash

set -Eeuo pipefail

if [ $# != 1 ]; then
  echo 'missing path to challenge directory'
  exit 1
fi

CHALLENGE_DIR=$1
CHALLENGE_NAME=$(basename "${CHALLENGE_DIR}")

kubectl create -f "${CHALLENGE_DIR}/expose.yaml"
echo 'waiting for load balancer to come up, ctrl-c if you don'"'"'t care'
while sleep 5; do
  LB_IP=$(kubectl get services | grep "${CHALLENGE_NAME}" | awk '{print $4}')
  if [ "${LB_IP}" != "<pending>" ]; then
    break;
  fi
done

echo "Challenge running at ${LB_IP}"
