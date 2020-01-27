#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

if [ $# != 1 ]; then
    echo "usage: $0 /path/to/challenge/directory"
    exit 1
fi

CHALLENGE_DIR=$1

if [ ! -d ${CHALLENGE_DIR} ]; then
    if [ -e ${CHALLENGE_DIR} ]; then
        echo "error: ${CHALLENGE_DIR} already exists and is not a directory"
        exit 1
    fi
    echo "creating ${CHALLENGE_DIR}"
    mkdir -p "${CHALLENGE_DIR}"
fi

CHALLENGE_DIR=$(realpath -L ${CHALLENGE_DIR})

mkdir -p "${CONFIG_DIR}"
ln -fs "${CHALLENGE_DIR}" "${CONFIG_DIR}/challenges"
if [ -f "${CONFIG_DIR}/cluster.conf" ]; then
    source "${CONFIG_DIR}/cluster.conf"
    # cluster.conf sets CHAL_DIR variable
    # check if it's the same
    if [ "${CHALLENGE_DIR}" != "${CHAL_DIR}" ]; then
        echo 'unsetting cluster.conf from different challenge directory: ' $(readlink "${CONFIG_DIR}/cluster.conf")
        rm "${CONFIG_DIR}/cluster.conf"
    fi
else
    if [ -L "${CONFIG_DIR}/cluster.conf" ]; then
        rm "${CONFIG_DIR}/cluster.conf"
    fi
fi
