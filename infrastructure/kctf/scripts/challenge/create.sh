#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_chal_dir

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR="${CHAL_DIR}/${CHALLENGE_NAME}"

if [ -d "${CHALLENGE_DIR}" ]; then
  echo 'challenge already exists'
  exit 1
fi

umask a+rx
cp -r "${CHAL_DIR}/kctf-conf/base/challenge-skeleton" "${CHALLENGE_DIR}"

pushd "${CHALLENGE_DIR}"

sed -i "s/challenge-skeleton/${CHALLENGE_NAME}/g" */*.yaml healthcheck/*/*.yaml

popd
