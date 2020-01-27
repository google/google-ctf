CONFIG_DIR="${HOME}/.config/kctf"
CONFIG_FILE="${CONFIG_DIR}/cluster.conf"
CHAL_DIR_LINK="${CONFIG_DIR}/challenges"

function load_chal_dir {
  if [ ! -d ${CHAL_DIR_LINK} ]; then
    echo 'error: challenge directory not set, please run kctf-setup-chal-dir'
    exit 1
  fi
  CHAL_DIR=$(readlink "${CHAL_DIR_LINK}")
  echo "CHAL_DIR: ${CHAL_DIR}"
}

function generate_config_dir {
  echo 'config dir'
  echo "CHAL_DIR: ${CHAL_DIR}"
  ret="${CHAL_DIR}/kctf-conf/${PROJECT}_${ZONE}_${CLUSTER_NAME}"
  echo 'config dir done'
}

function generate_config_path {
  echo "CHAL_DIR: ${CHAL_DIR}"
  echo 'config path'
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
  echo "CHAL_DIR: ${CHAL_DIR}"

  generate_config_path
  if [ "${ret}" != "${CONFIG_PATH}" ]; then
    echo "error: config path not at expected location: ${CONFIG_PATH} != ${ret}"
    exit 1
  fi
}
