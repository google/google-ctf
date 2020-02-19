#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

MIN_NODES="3"
MAX_NODES="8"
NUM_NODES="4"
MACHINE_TYPE="n1-standard-1"

gcloud container clusters create --enable-network-policy --enable-autoscaling --min-nodes ${MIN_NODES} --max-nodes ${MAX_NODES} --num-nodes ${NUM_NODES} --create-subnetwork name=kctf-${CLUSTER_NAME}-subnet --no-enable-master-authorized-networks --enable-ip-alias --enable-private-nodes --master-ipv4-cidr 172.16.0.32/28 --enable-autorepair --preemptible --machine-type ${MACHINE_TYPE} ${CLUSTER_NAME}

gcloud compute routers create kctf-${CLUSTER_NAME}-nat-router --network=default --region ${ZONE::-2}
gcloud compute routers nats create kctf-${CLUSTER_NAME}-nat-config --router-region europe-west4 --router kctf-${CLUSTER_NAME}-nat-router --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips

get_cluster_creds

kubectl create -f "${DIR}/config/apparmor.yaml"
kubectl create -f "${DIR}/config/daemon.yaml"
kubectl create -f "${DIR}/config/network-policy.yaml"
kubectl create -f "${DIR}/config/allow-dns.yaml"
kubectl patch ServiceAccount default --patch "automountServiceAccountToken: false"
# https://cloud.google.com/kubernetes-engine/docs/security-bulletins#may-14-2019
kubectl create -f "https://raw.githubusercontent.com/GoogleCloudPlatform/k8s-node-tools/master/disable-smt/gke/disable-smt.yaml"
