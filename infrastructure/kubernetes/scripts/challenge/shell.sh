#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."

if [ ! -f ~/.config/kctf/cluster.conf ]; then
    echo 'cluster config not found, please create or load it first'
    exit 1
fi
source ~/.config/kctf/cluster.conf

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")

echo "Select which instance to shell into:"
select pod in $(kubectl get pods -l "app=${CHALLENGE_NAME}" -o name); do
    kubectl exec "${pod:4}" -it -- bash
    break
done
