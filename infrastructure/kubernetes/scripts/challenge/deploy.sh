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
echo 'config loaded'
echo "CLUSTER_NAME: ${CLUSTER_NAME}"
CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")
generate_config_dir
CLUSTER_CONF_DIR="${ret}/${CHALLENGE_NAME}"

function delete_resource {
  local RESOURCE="$1"
  kubectl get "${RESOURCE}" >/dev/null && kubectl delete "${RESOURCE}"
}

pushd "${CHALLENGE_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}" .
docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"

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
  name: "${CHALLENGE_NAME}-deployment"
spec:
  template:
    spec:
      containers:
      - name: "${CHALLENGE_NAME}"
        image: "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"
EOF
fi

delete_resource "secret/${CHALLENGE_NAME}-secrets"
kubectl create -k secrets

delete_resource "deployment/${CHALLENGE_NAME}-deployment"
# This will use the kustomization.yaml to spawn the containers.yaml
kubectl create -k "${CLUSTER_CONF_DIR}"

delete_resource "hpa/${CHALLENGE_NAME}-hpa"
kubectl create -f "k8s/autoscaling.yaml"

delete_resource "configMap/${CHALLENGE_NAME}-config"
kubectl create -k config

popd
