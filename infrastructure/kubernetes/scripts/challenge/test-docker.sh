#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
load_chal_dir
echo 'challenge directory loaded'
CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")
pushd "${CHALLENGE_DIR}"

source chal.conf

build_nsjail_docker
docker build -t "test-${CHALLENGE_NAME}" .
docker run -d -p 1337:1337 --mount type=bind,source="/sys/fs/cgroup",target=/cgroup --mount type=bind,source="$(pwd)"/config,target=/config --mount type=bind,source="$(pwd)"/secrets,target=/secrets --privileged -it "test-${CHALLENGE_NAME}"
echo listening on port 1337
