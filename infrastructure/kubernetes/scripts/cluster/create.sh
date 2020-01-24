#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."

if [ ! -f ~/.config/kctf/cluster.conf ]; then
    echo 'cluster config not found, please create or load it first'
    exit 1
fi
source ~/.config/kctf/cluster.conf

echo 'building nsjail container'
pushd $DIR/util/nsjail-docker
docker build -qt "eu.gcr.io/${PROJECT}/nsjail" .
docker push "eu.gcr.io/${PROJECT}/nsjail"
popd

if [ ! -x $(which kubectl) ]; then
  gcloud components install kubectl
fi

gcloud config set project ${PROJECT}
gcloud config set compute/zone ${ZONE}

gcloud container clusters create --enable-network-policy --enable-autoscaling --min-nodes ${MIN_NODES} --max-nodes ${MAX_NODES} --num-nodes ${NUM_NODES} --enable-autorepair --machine-type ${MACHINE_TYPE} ${CLUSTER_NAME}

gcloud container clusters get-credentials ${CLUSTER_NAME}

kubectl create -f "${DIR}/config/network-policy.yaml"
kubectl create -f "${DIR}/config/allow-dns.yaml"
kubectl patch ServiceAccount default --patch "automountServiceAccountToken: false"
