#!/bin/bash

set -Eeuo pipefail

source cluster_vars

gcloud components install kubectl

gcloud config set project ${PROJECT}
gcloud config set compute/zone ${ZONE}

gcloud container clusters create --enable-network-policy --enable-autoscaling --min-nodes ${MIN_NODES} --max-nodes ${MAX_NODES} --num-nodes ${NUM_NODES} --enable-autorepair --machine-type ${MACHINE_TYPE} ${CLUSTER_NAME}

gcloud container clusters get-credentials ${CLUSTER_NAME}

kubectl create -f network-policy.yaml
kubectl create -f allow-dns.yaml
kubectl patch ServiceAccount default --patch "automountServiceAccountToken: false"
