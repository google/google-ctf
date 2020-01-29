#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

if [ $# != 1 ]; then
    echo "usage: $0 /path/to/challenge/directory"
    exit 1
fi

CHAL_DIR=$1

if [ ! -d ${CHAL_DIR} ]; then
    if [ -e ${CHAL_DIR} ]; then
        echo "error: ${CHAL_DIR} already exists and is not a directory"
        exit 1
    fi
    echo "creating ${CHAL_DIR}"
    mkdir -p "${CHAL_DIR}"
fi

CHAL_DIR=$(realpath -L ${CHAL_DIR})

mkdir -p "${CONFIG_DIR}"
ln -nfs "${CHAL_DIR}" "${CONFIG_DIR}/challenges"
if [ -f "${CONFIG_DIR}/cluster.conf" ]; then
    source "${CONFIG_DIR}/cluster.conf"

    CONFIG_PATH=$(readlink "${CONFIG_DIR}/cluster.conf")
    generate_config_path
    if [ "${ret}" != "${CONFIG_PATH}" ]; then
        echo "unsetting cluster.conf from different challenge directory: ${CONFIG_PATH}"
        rm "${CONFIG_DIR}/cluster.conf"
    fi
else
    # remove dangling link
    if [ -L "${CONFIG_DIR}/cluster.conf" ]; then
        rm "${CONFIG_DIR}/cluster.conf"
    fi
fi
