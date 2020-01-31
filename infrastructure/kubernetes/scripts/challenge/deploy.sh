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

pushd "${CHALLENGE_DIR}"

source chal.conf

if [ ! "${DEPLOY}" = "true" ]; then
  echo "aborting: DEPLOY=${DEPLOY} in chal.conf"
  exit 1
fi

build_nsjail_docker
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
  name: "${CHALLENGE_NAME}"
spec:
  template:
    spec:
      containers:
      - name: "challenge"
        image: "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}"
      - name: "healthcheck"
        image: "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}-healthcheck"
EOF
fi

# Create the load balancer first since it takes a while to come up
if [ "${PUBLIC}" = "true" ]; then
  if ! kubectl get "service/${CHALLENGE_NAME}" >/dev/null 2>&1; then
    kubectl create -f "${CHALLENGE_DIR}/k8s/network.yaml"
  else
    echo 're-using existing load balancer'
  fi
else
  # if not marked as public, try to delete an existing load balancer
  delete_resource "service/${CHALLENGE_NAME}"
fi

pushd healthcheck
  for f in $(find exploit); do
    TZ="UTC" touch -a -m -t 198001010000.00 $f
  done
  find exploit -print0 | sort -z | cpio -0 --reproducible -R 0:0 -o > exploit.cpio
  KEY="$(sha256sum exploit.cpio | awk '{print $1}')"
  openssl aes-256-cbc -e -in exploit.cpio -out exploit.cpio.enc -K "${KEY}" -nosalt -iv 00000000000000000000000000000000
  docker build -t "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}-healthcheck" .
  docker push "eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}-healthcheck"
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

delete_resource "hpa/${CHALLENGE_NAME}"
kubectl create -f "k8s/autoscaling.yaml"

if [ "${PUBLIC}" = "true" ]; then
  echo '== CHALLENGE IS PUBLIC =='
  if [ "${KCTF_DONT_WAIT_LB}" != "true" ]; then
    echo 'Waiting for load balancer to come up, Ctrl-C if you don'"'"'t care'
    LB_IP=$($DIR/scripts/challenge/ip.sh "${CHALLENGE_NAME}")
    echo "Running at ${LB_IP}"
  fi
fi

popd
