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

delete_resource "secret/${CHALLENGE_NAME}-secrets"
delete_resource "deployment/${CHALLENGE_NAME}"
delete_resource "hpa/${CHALLENGE_NAME}"
delete_resource "configMap/${CHALLENGE_NAME}-config"
delete_resource "service/${CHALLENGE_NAME}"
