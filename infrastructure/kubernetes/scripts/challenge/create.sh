#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
CONFIG_DIR="${HOME}/.config/kctf"

if [ ! -d ${CONFIG_DIR}/challenges ]; then
    echo 'challenge directory not found, please run kctf-setup-chal-dir'
    exit 1
fi
CHAL_DIR=$(readlink "${CONFIG_DIR}/challenges")

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

cp -r "${DIR}/util/challenge-skeleton" "${CHALLENGE_DIR}"

pushd "${CHALLENGE_DIR}"

sed -i "s/challenge-skeleton/${CHALLENGE_NAME}/g" config/*.yaml

popd
