#!/bin/bash

set -Eeuo pipefail

if [ $# != 1 ]; then
  echo 'missing path to challenge directory'
  exit 1
fi

CHALLENGE_DIR=$1
CHALLENGE_NAME=$(basename "${CHALLENGE_DIR}")

kubectl delete "secret/${CHALLENGE_NAME}-flag"
kubectl delete "configMap/${CHALLENGE_NAME}-pow" || true
kubectl delete -f "${CHALLENGE_DIR}/challenge.yaml"
kubectl delete -f "${CHALLENGE_DIR}/autoscaling.yaml"
kubectl delete -f "${CHALLENGE_DIR}/expose.yaml" || echo 'ignoring error trying to delete the load balancer'
