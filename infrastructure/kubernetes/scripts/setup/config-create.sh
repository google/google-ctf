#!/bin/bash

set -Eeuo pipefail
cd $(dirname $(readlink -f $0))

# Default Configuration

CHAL_DIR=""
PROJECT=""
ZONE="europe-west3-c"
MIN_NODES="3"
MAX_NODES="20"
NUM_NODES="3"
MACHINE_TYPE="n1-standard-4"
CLUSTER_NAME="ctf-cluster-eu"
DOMAIN_NAME=""

config=""
read_config() {
    read -e -p "  $2: " -i "${!1}" "$1"
    line=$(declare -p "$1")
    config="${config}"$'\n'"${line}"
}

echo "= Challenges Directory ="
echo
read -e -p "  In which directory will challenges be stored?: " "CHAL_DIR"
eval CHAL_DIR="${CHAL_DIR}"
if [ ! -d "${CHAL_DIR}" ]; then
    echo "creating ${CHAL_DIR}"
    mkdir -p "${CHAL_DIR}"
fi
line=$(declare -p "CHAL_DIR")
config="${config}"$'\n'"${line}"
echo

CONFIG_FILE="${CHAL_DIR}/kctf.conf"
if test -f "$CONFIG_FILE"; then
    echo "= WARNING ="
    read -s -p "Config file already exists, this program will overwrite it. Press Ctrl+C to cancel, Enter to continue."
    echo
    echo
    . "$CONFIG_FILE"
fi

echo "= CLUSTER CONFIGURATION ="
echo
echo "== PROJECT NAME =="
echo
echo " Important: Make sure to update this field to your own project, or nothing will work"
echo
read_config PROJECT "Google Cloud Platform project name"
echo
echo "= OPTIONAL CONFIGURATION ="
echo
echo " Note: You can leave everything below here as defaults."
echo
echo "== ZONE =="
echo
echo " Used for cluster configuration"
echo "  The zone defines the geographic location of the cluster."
echo
echo -n "  Available zones: (Loading...)"
gcloud compute zones list --format="csv[no-heading](name)" | xargs echo -e "\r  Available zones: "
echo
read_config ZONE "GCP Zone"
echo
echo "== AUTOSCALING =="
echo
echo " Used for autoscaling configuration"
echo "  A node is a VM, here you can configure how many VMs your cluster will have."
echo
read_config MIN_NODES "Minimum number of nodes"
read_config MAX_NODES "Maximum number of nodes"
read_config NUM_NODES "Initial number of nodes"
echo
echo "== VM CONFIGURATION =="
echo
echo " Select the VM type for the nodes"
echo "  n1-standard-4 means a 4 vCPUs VM of N1 gen with a standard RAM (15G for 4CPUs)."
echo "  n1-highmem-4 means a 4 vCPUs VM of N1 gen with more RAM (27G for 4CPUs)."
echo "  n1-highcpu-4 means a 4 vCPUs VM of N1 gen with less RAM (3G for 4CPUs)."
echo
echo -n "  Available machine types: (Loading...)"
gcloud compute machine-types list --zones="${ZONE}" --format="csv[no-heading](name)" | xargs echo -e "\r  Available machine types: "
echo
read_config MACHINE_TYPE "The VM machine type"
echo
echo "== CLUSTER NAME =="
echo
echo "  If you are reusing the same project for multiple CTFs, make sure this name is unique."
echo
read_config CLUSTER_NAME "Name of the cluster"
echo
echo "== DOMAIN NAME =="
echo
echo "  If you want to configure a domain name for the challenge, provide it below, otherwise leave it empty."
echo
read_config DOMAIN_NAME "Domain name (eg, k8s.ctfcompetititon.com)"
echo
echo "= SUMMARY ="
echo " This is the configuration for your cluster, please review it to make sure it is correct."
echo "$config"
echo
echo " If you wish to change anything, just run this command again."

mkdir -p "${HOME}/.config/kctf"
echo "${config}" > "$CONFIG_FILE"
ln -fs "${CONFIG_FILE}" "${HOME}/.config/kctf/cluster.conf"
