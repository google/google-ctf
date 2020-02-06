#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

if [ $# != 1 ]; then
    echo 'missing path to config'
    exit 1
fi

CONFIG_FILE=$1
source ${CONFIG_FILE}

# sanity check
if [ -z ${CLUSTER_NAME} ]; then
    echo 'error: CLUSTER_NAME not in config. Valid config file?'
    exit 1
fi
if [ -z ${PROJECT} ]; then
    echo 'error: PROJECT not in config. Valid config file?'
    exit 1
fi

echo "loaded config for ${CLUSTER_NAME} in ${PROJECT}"

mkdir -p "${HOME}/.config/kctf"
ln -fs "${CONFIG_FILE}" "${HOME}/.config/kctf/cluster.conf"

create_gcloud_config

# there might be an existing cluster, try to get the creds
get_cluster_creds 2>/dev/null || true
