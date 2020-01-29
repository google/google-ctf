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

LB_IP=""
while [ -z "${LB_IP}" ]; do
  LB_IP=$(kubectl get "service/${CHALLENGE_NAME}-lb-service" -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')
  sleep 3
done

echo "${LB_IP}"
