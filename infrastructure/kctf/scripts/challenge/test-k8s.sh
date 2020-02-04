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
CLUSTER_CONF_DIR="${CHAL_DIR}/kube-ctf/minikube/${CHALLENGE_NAME}"
PROJECT="local-minikube"

pushd "${CHALLENGE_DIR}"

source chal.conf

build_nsjail_docker
VERSION="live"
docker build -t "${PROJECT}-${CHALLENGE_NAME}:${VERSION}" .

if [ ! -d "${CLUSTER_CONF_DIR}" ]; then
  mkdir -p "${CLUSTER_CONF_DIR}"
  cat > "${CLUSTER_CONF_DIR}/kustomization.yaml" << EOF
bases:
- "../../../${CHALLENGE_NAME}/k8s"
patchesStrategicMerge:
- "update_image_name.yaml"
EOF
  cat > "${CLUSTER_CONF_DIR}/update_image_name.yaml" << EOF
apiVersion: "apps/v1"
kind: "Deployment"
metadata:
  name: "${CHALLENGE_NAME}"
spec:
  template:
    spec:
      containers:
      - name: "challenge"
        image: "${PROJECT}-${CHALLENGE_NAME}:${VERSION}"
        imagePullPolicy: Never
      - name: "healthcheck"
        image: "${PROJECT}-${CHALLENGE_NAME}-healthcheck:${VERSION}"
        imagePullPolicy: Never
EOF
fi

pushd healthcheck
  for f in $(find exploit); do
    TZ="UTC" touch -a -m -t 198001010000.00 $f
  done
  find exploit -print0 | sort -z | cpio -0 --reproducible -R 0:0 -o > exploit.cpio
  KEY="$(sha256sum exploit.cpio | awk '{print $1}')"
  openssl aes-256-cbc -e -in exploit.cpio -out exploit.cpio.enc -K "${KEY}" -nosalt -iv 00000000000000000000000000000000
  docker build -t "${PROJECT}-${CHALLENGE_NAME}-healthcheck:${VERSION}" .
  rm exploit.cpio exploit.cpio.enc

  delete_resource "secret/${CHALLENGE_NAME}-healthcheck-secrets"
  echo -n "${KEY}" > secrets/exploit.key
  kubectl create -k secrets
  # delete the key again so that it doesn't end up in the challenge repo
  rm secrets/exploit.key

  delete_resource "configMap/${CHALLENGE_NAME}-healthcheck-config"
  kubectl create -k config
popd

delete_resource "secret/${CHALLENGE_NAME}-secrets"
kubectl create -k secrets

delete_resource "configMap/${CHALLENGE_NAME}-config"
kubectl create -k config

delete_resource "deployment/${CHALLENGE_NAME}"
# This will use the kustomization.yaml to spawn the containers.yaml
kubectl create -k "${CLUSTER_CONF_DIR}"
# Disable apparmor
kubectl patch deployment "${CHALLENGE_NAME}"  --type json -p='[{"op":"remove","path":"/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1challenge"}]'

delete_resource "hpa/${CHALLENGE_NAME}"
kubectl create -f "k8s/autoscaling.yaml"

popd
