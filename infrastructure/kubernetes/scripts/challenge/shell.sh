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

echo "Select which instance to shell into:"
select pod in $(kubectl get pods -l "app=${CHALLENGE_NAME}" -o name); do
    kubectl exec "${pod:4}" -it -- bash
    break
done
