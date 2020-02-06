#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

MIN_NODES="1"
MAX_NODES="1"
NUM_NODES="1"
MACHINE_TYPE="n1-standard-2"

gcloud container clusters create --enable-network-policy --enable-autoscaling --min-nodes ${MIN_NODES} --max-nodes ${MAX_NODES} --num-nodes ${NUM_NODES} --enable-autorepair --machine-type ${MACHINE_TYPE} ${CLUSTER_NAME}

get_cluster_creds

kubectl create -f "${DIR}/config/apparmor.yaml"
kubectl create -f "${DIR}/config/daemon.yaml"
kubectl create -f "${DIR}/config/network-policy.yaml"
kubectl create -f "${DIR}/config/allow-dns.yaml"
kubectl patch ServiceAccount default --patch "automountServiceAccountToken: false"
