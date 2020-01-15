#!/bin/bash

set -Eeuo pipefail

source cluster_vars

gcloud components install kubectl
gcloud container clusters get-credentials ${CLUSTER_NAME}
gcloud auth configure-docker
