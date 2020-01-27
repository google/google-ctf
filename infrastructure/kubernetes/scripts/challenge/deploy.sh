#!/bin/bash

set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."

if [ ! -f ~/.config/kctf/cluster.conf ]; then
    echo 'cluster config not found, please create or load it first'
    exit 1
fi
source ~/.config/kctf/cluster.conf

if [ $# != 1 ]; then
    echo 'missing challenge name'
    exit 1
fi

CHALLENGE_NAME=$1
CHALLENGE_DIR=$(readlink -f "${CHAL_DIR}/${CHALLENGE_NAME}")
CLUSTER_CONF_DIR="${CHAL_DIR}/kctf-conf/${PROJECT}_${ZONE}_${CLUSTER_NAME}/${CHALLENGE_NAME}"

pushd "${CHALLENGE_DIR}"

docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}" .
docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"
kubectl create secret generic "${CHALLENGE_NAME}-flag" --from-file="secrets/flag"

mkdir -p "${CLUSTER_CONF_DIR}"
cat > "${CLUSTER_CONF_DIR}/kustomization.yaml" << EOF
bases:
- "../../../${CHALLENGE_NAME}/config"
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

pushd config
# This will use the kustomization.yaml to spawn the containers.yaml
kubectl create -k "${CLUSTER_CONF_DIR}"
kubectl create -f "autoscaling.yaml"
if [ -f pow.yaml ]; then
  kubectl create -f "pow.yaml"
fi

popd

popd
