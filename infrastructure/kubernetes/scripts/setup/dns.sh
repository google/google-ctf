#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source $DIR/config/CLUSTER_VARS

gcloud dns managed-zones create "${CLUSTER_NAME}-dns-zone" --description "DNS Zone for ${DOMAIN_NAME}" --dns-name="${DOMAIN_NAME}."
