#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config


# Name will be per-cluster
SUFFIX=$(echo "${PROJECT}-${CLUSTER_NAME}-${ZONE}" | sha1sum)
BUCKET_NAME="kctf-gcsfuse-${SUFFIX:0:16}"
GSA_NAME="${BUCKET_NAME}"

GSA_EMAIL=$(gcloud iam service-accounts list --filter "name:${GSA_NAME}" --format 'get(email)' || true)

if [ -z "${GSA_EMAIL}" ]; then
  gcloud iam service-accounts create "${GSA_NAME}" --description "service account used for GCS filesystem ${PROJECT} ${CLUSTER_NAME} ${ZONE}" --display-name "kCTF GCSFUSE service account ${PROJECT} ${CLUSTER_NAME} ${ZONE}"
  GSA_EMAIL=$(gcloud iam service-accounts list --filter "name:${GSA_NAME}" --format 'get(email)')
fi

if ! gsutil du "gs://${BUCKET_NAME}/"; then
  gsutil mb -l eu "gs://${BUCKET_NAME}/"
  gsutil uniformbucketlevelaccess set on "gs://${BUCKET_NAME}/"
fi

gcloud projects add-iam-policy-binding "${PROJECT}" --member "serviceAccount:${GSA_EMAIL}" --role roles/storage.objectAdmin

KEY_PATH=$(mktemp -d)/key.json

gcloud iam service-accounts keys create "${KEY_PATH}" --iam-account "${GSA_EMAIL}"

kubectl create secret generic gcsfuse-secrets --dry-run -o yaml --from-file="${KEY_PATH}" --namespace kube-system | kubectl replace -f -

rm -rf $KEY_PATH

kubectl create configmap gcsfuse-config --dry-run -o yaml --from-literal=gcs_bucket="${BUCKET_NAME}" --namespace kube-system | kubectl replace -f -

kubectl rollout restart daemonset/ctf-daemon-gcsfuse --namespace kube-system
