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

echo
echo "= INSTANCES / PODs ="
echo
echo "Challenge execution status"
echo "This shows you how many instances of the challenges are running."
echo
kubectl get pods -l "app=${CHALLENGE_NAME}" -o wide
echo
echo
echo "= DEPLOYMENTS ="
echo
echo "Challenge deployment status"
echo "This shows you if the challenge was deployed to the cluster."
echo
kubectl get deployments -l "app=${CHALLENGE_NAME}" -o wide
echo
echo "= EXTERNAL SERVICES ="
echo
echo "Challenge external status"
echo "This shows you if the challenge is exposed externally."
echo
kubectl get services -l "app=${CHALLENGE_NAME}" -o wide
echo
