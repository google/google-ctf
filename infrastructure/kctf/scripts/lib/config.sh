CONFIG_DIR="${HOME}/.config/kctf"
CONFIG_FILE="${CONFIG_DIR}/cluster.conf" CHAL_DIR_LINK="${CONFIG_DIR}/challenges"
export KUBECONFIG="${CONFIG_DIR}/kube.conf"

function load_chal_dir {
  if [ ! -d ${CHAL_DIR_LINK} ]; then
    echo 'error: challenge directory not set, please run kctf-setup-chal-dir'
    exit 1
  fi
  CHAL_DIR=$(readlink "${CHAL_DIR_LINK}")
}

function generate_config_dir {
  ret="${CHAL_DIR}/kctf-conf/${PROJECT}_${ZONE}_${CLUSTER_NAME}"
}

function generate_config_path {
  generate_config_dir
  ret="${ret}/cluster.conf"
}

function load_config {
  if [ ! -f ${CONFIG_FILE} ]; then
    echo 'error: cluster config required, please create or load a cluster config first'
    exit 1
  fi
  source "${CONFIG_DIR}/cluster.conf"
  CONFIG_PATH=$(readlink "${CONFIG_DIR}/cluster.conf")

  load_chal_dir

  generate_config_path
  if [ "${ret}" != "${CONFIG_PATH}" ]; then
    echo "error: config path not at expected location: ${CONFIG_PATH} != ${ret}"
    exit 1
  fi

  load_gcloud_config

  # try to load the kube config
  if ! kubectl config use-context "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}" 2> /dev/null; then
    # fall back to an empty config
    kubectl config set-context nocluster
    kubectl config use-context nocluster
  fi
}

function build_nsjail_docker {
  echo 'building nsjail container'
  make -C "${CHAL_DIR}/kctf-conf/base/nsjail-docker" docker
}

function delete_resource {
  local RESOURCE="$1"
  kubectl get "${RESOURCE}" >/dev/null 2>&1 && kubectl delete "${RESOURCE}" || true
}

function gcloud_config_name {
  ret="kctf-$(echo \"${PROJECT}_${ZONE}_${CLUSTER_NAME}\" | md5sum | awk '{print $1}')"
}

function create_gcloud_config {
  gcloud_config_name
  CONFIG_NAME="${ret}"
  ACTIVE_ACCOUNT="$(gcloud config get-value core/account)"
  export CLOUDSDK_ACTIVE_CONFIG_NAME="${CONFIG_NAME}"
  if ! gcloud config configurations describe "${CONFIG_NAME}" >/dev/null 2>&1; then
      gcloud config configurations create --no-activate "${CONFIG_NAME}"
      gcloud config set core/account "${ACTIVE_ACCOUNT}"
      gcloud config set core/project "${PROJECT}"
      gcloud config set compute/zone "${ZONE}"
      gcloud config set container/cluster "${CLUSTER_NAME}"
  fi
}

function load_gcloud_config {
  gcloud_config_name
  CONFIG_NAME="${ret}"
  export CLOUDSDK_ACTIVE_CONFIG_NAME="${CONFIG_NAME}"
}

function get_cluster_creds {
  gcloud container clusters get-credentials "${CLUSTER_NAME}"
  kubectl config delete-context "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}" 2>/dev/null || true
  kubectl config rename-context "gke_${PROJECT}_${ZONE}_${CLUSTER_NAME}" "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}"
}
