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

kubectl create -f "${CHALLENGE_DIR}/expose.yaml"
echo 'Waiting for load balancer to come up, Ctrl-C if you don'"'"'t care'

LB_IP=$($DIR/scripts/challenge/ip.sh "${CHALLENGE_NAME}")

echo "Challenge running at ${LB_IP}"
