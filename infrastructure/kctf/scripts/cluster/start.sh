#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

MIN_NODES="1"
MAX_NODES="2"
NUM_NODES="1"
MACHINE_TYPE="n2-standard-4"

gcloud container clusters create --enable-network-policy --enable-autoscaling --min-nodes ${MIN_NODES} --max-nodes ${MAX_NODES} --num-nodes ${NUM_NODES} --create-subnetwork name=kctf-${CLUSTER_NAME}-subnet --no-enable-master-authorized-networks --enable-ip-alias --enable-private-nodes --master-ipv4-cidr 172.16.0.32/28 --enable-autorepair --preemptible --machine-type ${MACHINE_TYPE} ${CLUSTER_NAME}

gcloud compute routers create kctf-${CLUSTER_NAME}-nat-router --network=default --region ${ZONE::-2}
gcloud compute routers nats create kctf-${CLUSTER_NAME}-nat-config --router-region europe-west4 --router kctf-${CLUSTER_NAME}-nat-router --nat-all-subnet-ip-ranges --auto-allocate-nat-external-ips

get_cluster_creds

# GCSFUSE

SUFFIX=$(echo "${PROJECT}-${CLUSTER_NAME}-${ZONE}" | sha1sum)
BUCKET_NAME="kctf-gcsfuse-${SUFFIX:0:16}"
GSA_NAME="${BUCKET_NAME}"
GSA_EMAIL=$(gcloud iam service-accounts list --filter "name:${GSA_NAME}" --format 'get(email)' || true)
if [ -z "${GSA_EMAIL}" ]; then
  gcloud iam service-accounts create "${GSA_NAME}" --description "kCTF GCSFUSE service account ${CLUSTER_NAME} ${ZONE}" --display-name "kCTF GCSFUSE ${CLUSTER_NAME} ${ZONE}"
  GSA_EMAIL=$(gcloud iam service-accounts list --filter "name:${GSA_NAME}" --format 'get(email)')
fi
if ! gsutil du "gs://${BUCKET_NAME}/"; then
  gsutil mb -l eu "gs://${BUCKET_NAME}/"
  gsutil uniformbucketlevelaccess set on "gs://${BUCKET_NAME}/"
fi
gcloud projects add-iam-policy-binding "${PROJECT}" --member "serviceAccount:${GSA_EMAIL}" --role roles/storage.objectAdmin

KEY_PATH=$(mktemp -d)/key.json

gcloud iam service-accounts keys create "${KEY_PATH}" --iam-account "${GSA_EMAIL}"

kubectl create secret generic gcsfuse-secrets --from-file="${KEY_PATH}" --namespace kube-system

rm -rf $(dirname "${KEY_PATH}")

kubectl create configmap gcsfuse-config --from-literal=gcs_bucket="${BUCKET_NAME}" --namespace kube-system

kubectl create -f "${DIR}/config/daemon-gcsfuse.yaml"


kubectl create -f "${DIR}/config/apparmor.yaml"
kubectl create -f "${DIR}/config/daemon.yaml"
kubectl create -f "${DIR}/config/network-policy.yaml"
kubectl create -f "${DIR}/config/allow-dns.yaml"
kubectl patch ServiceAccount default --patch "automountServiceAccountToken: false"
