#!/bin/bash
# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -Eeuo pipefail
DIR="$( cd "$( dirname "$( readlink -f "${BASH_SOURCE[0]}")" )" >/dev/null && pwd )/../.."
source "${DIR}/scripts/lib/config.sh"

load_config

gcloud config set project ${PROJECT}
gcloud config set compute/zone ${ZONE}

OLD_POOL_NAME=$(gcloud container node-pools list --cluster ${CLUSTER_NAME} --format 'value(name)')
if [ $(echo "${OLD_POOL_NAME}" | wc -l) != "1" ]; then
  echo 'error: this script expects exactly one node pool'
  echo '== node pools =='
  echo "${OLD_POOL_NAME}"
  exit 1
fi

echo
echo '= Current node pool ='
echo
gcloud container node-pools describe "${OLD_POOL_NAME}" --cluster ${CLUSTER_NAME} --format 'table(name, config.machineType, initialNodeCount, autoscaling.minNodeCount, autoscaling.maxNodeCount)'

MACHINE_TYPE="n2-standard-4"
MIN_NODES="1"
MAX_NODES="1"
NUM_NODES="1"
NEW_POOL_NAME="${OLD_POOL_NAME}-resized"

echo
echo '= New node pool config ='
echo
echo '== NAME =='
echo
while true; do
  read -e -p "  Node pool name: " -i "${NEW_POOL_NAME}" NEW_POOL_NAME
  if [ "${OLD_POOL_NAME}" = "${NEW_POOL_NAME}" ]; then
    echo "  error: can't use the name of the existing node pool"
  else
    break
  fi
done
echo
echo '== AUTOSCALING =='
echo
read -e -p "  Initial number of nodes: " -i "${NUM_NODES}" NUM_NODES
read -e -p "  Minimum number of nodes: " -i "${MIN_NODES}" MIN_NODES
read -e -p "  Maximum number of nodes: " -i "${MAX_NODES}" MAX_NODES
echo
echo '== VM CONFIGURATION =='
echo
echo " Select the VM type for the nodes"
echo "  n1-standard-4 means a 4 vCPUs VM of N1 gen with a standard RAM (15G for 4CPUs)."
echo "  n1-highmem-4 means a 4 vCPUs VM of N1 gen with more RAM (27G for 4CPUs)."
echo "  n1-highcpu-4 means a 4 vCPUs VM of N1 gen with less RAM (3G for 4CPUs)."
echo
echo -n "  Available machine types: (Loading...)"
gcloud compute machine-types list --zones="${ZONE}" --format="csv[no-heading](name)" | egrep '^n2' | xargs echo -e "\r  Available machine types: "
read -e -p "  Machine type: " -i "${MACHINE_TYPE}" MACHINE_TYPE

echo '= New config ='
echo
echo "NEW_POOL_NAME=${NEW_POOL_NAME}"
echo "NUM_NODES=${NUM_NODES}"
echo "MIN_NODES=${MIN_NODES}"
echo "MAX_NODES=${MAX_NODES}"
echo "MACHINE_TYPE=${MACHINE_TYPE}"
echo
read -p "Press enter to continue"
echo

gcloud container node-pools create "${NEW_POOL_NAME}" \
  --cluster="${CLUSTER_NAME}" \
  --machine-type="${MACHINE_TYPE}" \
  --enable-autorepair \
  --enable-autoupgrade \
  --num-nodes="${NUM_NODES}" \
  --enable-autoscaling \
  --min-nodes="${MIN_NODES}" \
  --max-nodes="${MAX_NODES}"

for node in $(kubectl get nodes -l cloud.google.com/gke-nodepool="${OLD_POOL_NAME}" -o=name); do
  kubectl cordon "$node"
done

for node in $(kubectl get nodes -l cloud.google.com/gke-nodepool="${OLD_POOL_NAME}" -o=name); do
  kubectl drain --force --ignore-daemonsets --delete-local-data --grace-period=10 "$node";
done

gcloud container node-pools delete "${OLD_POOL_NAME}" --cluster "${CLUSTER_NAME}"
