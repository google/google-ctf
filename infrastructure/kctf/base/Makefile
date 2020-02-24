#
#
#
# THIS MAKEFILE IS USED CTF-WIDE. IF YOU MAKE CHANGES IT WILL APPLY TO ALL CHALLENGES.
#
#
#
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

.PHONY: start stop docker ip status logs healthcheck-logs ssh healthcheck-ssh port-forward test-docker healthcheck-test-docker test-kind test-d4w .test-local clean .deploy .network .cluster-config .deployment .healthcheck-exploit-key-secret .FORCE

SHELL := bash
.ONESHELL:
.SHELLFLAGS = -e -c

PUSH_TARGET="REMOTE"

PROJECT:=CONFIGMISSING
CLUSTER_NAME:=CONFIGMISSING
ZONE:=CONFIGMISSING
# sets DEPLOY, PUBLIC and HEALTHCHECK
include chal.conf
-include $(HOME)/.config/kctf/cluster.conf
KUBECONFIG=$(HOME)/.config/kctf/kube.conf
export KUBECONFIG

CHALLENGE_NAME:=$(shell basename ${CURDIR})
CLUSTER_GEN=.gen/${PROJECT}_${ZONE}_${CLUSTER_NAME}

ifeq ($(HEALTHCHECK), true)
MAYBE_REMOTE_HEALTHCHECK_IMAGE=${CLUSTER_GEN}/remote-healthcheck-image
MAYBE_HEALTHCHECK=.healthcheck-exploit-key-secret ${CLUSTER_GEN}/healthcheck-image-pushed ${CLUSTER_GEN}/remote-healthcheck-image
else
MAYBE_REMOTE_HEALTHCHECK_IMAGE=
MAYBE_HEALTHCHECK=
endif

docker: .gen/docker-image

start:
ifeq ($(DEPLOY), true)
	  $(MAKE) .deploy
else
	  echo "skipping deployment: DEPLOY=\"$${DEPLOY}\""
endif

stop: .cluster-config
	for resource_type in deployment service hpa; do
	  kubectl get "$${resource_type}/${CHALLENGE_NAME}" >/dev/null 2>&1 && kubectl delete "$${resource_type}/${CHALLENGE_NAME}" || true
	done
	kubectl get "configMap/${CHALLENGE_NAME}-config" >/dev/null 2>&1 && kubectl delete "configMap/${CHALLENGE_NAME}-config" || true
	kubectl get "secret/${CHALLENGE_NAME}-secrets" >/dev/null 2>&1 && kubectl delete "secret/${CHALLENGE_NAME}-secrets" || true
	for resource in "secret/${CHALLENGE_NAME}-healthcheck-exploit-key" "secret/${CHALLENGE_NAME}-healthcheck-secrets" "configMap/${CHALLENGE_NAME}-healthcheck-config"; do
	  kubectl get "$${resource}" >/dev/null 2>&1 && kubectl delete "$${resource}" || true
	done

ip: .cluster-config
	LB_IP=""
	while [ -z "$${LB_IP}" ]; do
	  LB_IP=$$(kubectl get "service/${CHALLENGE_NAME}" -o=jsonpath='{.status.loadBalancer.ingress[0].ip}')
	  sleep 3
	done
	echo "$${LB_IP}"

status: .cluster-config
	@echo "= INSTANCES / PODs ="
	@echo
	@echo "Challenge execution status"
	@echo "This shows you how many instances of the challenges are running."
	@echo
	@kubectl get pods -l "app=${CHALLENGE_NAME}" -o wide
	@echo
	@echo
	@echo "= DEPLOYMENTS ="
	@echo
	@echo "Challenge deployment status"
	@echo "This shows you if the challenge was deployed to the cluster."
	@echo
	@kubectl get deployments -l "app=${CHALLENGE_NAME}" -o wide
	@echo
	@echo "= EXTERNAL SERVICES ="
	@echo
	@echo "Challenge external status"
	@echo "This shows you if the challenge is exposed externally."
	@echo
	@kubectl get services -l "app=${CHALLENGE_NAME}" -o wide
	@echo

logs: .cluster-config
	kubectl logs -l "app=${CHALLENGE_NAME}" -c challenge

healthcheck-logs: .cluster-config
	kubectl logs -l "app=${CHALLENGE_NAME}" -c healthcheck

ssh: .cluster-config
	kubectl exec deployment/${CHALLENGE_NAME} -c challenge -it /bin/bash

healthcheck-ssh: .cluster-config
	kubectl exec deployment/${CHALLENGE_NAME} -c healthcheck -it /bin/bash

port-forward: .cluster-config
	kubectl port-forward deployment/${CHALLENGE_NAME} :1337 &

test-docker: .gen/docker-id
	docker ps -f ancestor=kctf-chal-${CHALLENGE_NAME}

healthcheck-test-docker: .gen/healthcheck-docker-id
	docker ps -f ancestor=kctf-healthcheck-${CHALLENGE_NAME}

.gen/healthcheck-docker-id: .gen/docker-name .gen/healthcheck-docker-image
	test -s .gen/healthcheck-docker-id && docker kill $$(cat .gen/healthcheck-docker-id) || true
	docker run -d -it --network "container:$$(cat .gen/docker-name)" \
		--mount "type=bind,source=$(CURDIR)/healthcheck/config,target=/config"\
		--mount "type=bind,source=$(CURDIR)/healthcheck/secrets,target=/secrets"\
		--mount "type=bind,source=$(CURDIR)/healthcheck/.gen/exploit.key,target=/keys/exploit.key"\
		"kctf-healthcheck-${CHALLENGE_NAME}" > $@

.gen/docker-name: .gen/docker-id
	docker ps --all -f id=$$(cat .gen/docker-id) --format {{.Names}} > $@

.gen/docker-id: PUSH_TARGET="LOCAL_DOCKER"
.gen/docker-id: docker
	test -s .gen/docker-id && docker kill $$(cat .gen/docker-id) || true
	docker run -d -it -p 1337 \
		--mount "type=bind,source=$(CURDIR)/challenge/config,target=/config"\
		--mount "type=bind,source=$(CURDIR)/challenge/secrets,target=/secrets"\
		--privileged "kctf-chal-${CHALLENGE_NAME}" > $@

test-kind: LOCAL_KUBECONFIG=".gen/kind-kubeconfig"
test-kind: PUSH_TARGET="KIND"
test-kind: | .gen/kind-kubeconfig .test-local

test-d4w: LOCAL_KUBECONFIG=".gen/d4w-kubeconfig"
test-d4w: PUSH_TARGET="LOCAL_DOCKER"
test-d4w: | .gen/d4w-kubeconfig .test-local

.test-local: PROJECT="kctf-testing"
.test-local:
	kubectl config rename-context "$(shell kubectl config current-context --kubeconfig="${LOCAL_KUBECONFIG}")" "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}" --kubeconfig="${LOCAL_KUBECONFIG}" || true
	$(MAKE) .deploy PUSH_TARGET=${PUSH_TARGET} PROJECT=${PROJECT} ZONE=${ZONE} CLUSTER_NAME=${CLUSTER_NAME} KUBECONFIG="${LOCAL_KUBECONFIG}"
	kubectl patch deployment ${CHALLENGE_NAME}  --type json -p='[{"op": "remove", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1challenge"}]' --kubeconfig=${LOCAL_KUBECONFIG}

clean:
	rm -R .gen/* || true
	rm -R healthcheck/.gen/* || true

.deploy: .deployment .cluster-config .network

.network: .gen/k8s | .cluster-config
ifeq ($(PUBLIC), true)
	kubectl apply -k k8s/network
else
	kubectl get "service/${CHALLENGE_NAME}" >/dev/null 2>&1 && kubectl delete "service/${CHALLENGE_NAME}" || true
endif

.deployment: .gen/k8s ${CLUSTER_GEN}/image-pushed ${CLUSTER_GEN}/remote-image ${MAYBE_HEALTHCHECK} | .cluster-config
	kubectl apply -k k8s/deployment
	# update the challenge container if the image changed
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/image-tagged)"
	CHAL_IMAGE="$$(cat ${CLUSTER_GEN}/remote-image)"
	if [ "$${CHAL_IMAGE}" != "$${PUSHED_IMAGE}" ]; then
	  kubectl set image "deployment/${CHALLENGE_NAME}" "challenge=$${PUSHED_IMAGE}"
	fi
ifeq ($(HEALTHCHECK), true)
	# update the healthcheck container if the image changed
	PUSHED_HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/healthcheck-image-tagged)"
	HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/remote-healthcheck-image)"
	if [ "$${HEALTHCHECK_IMAGE}" != "$${PUSHED_HEALTHCHECK_IMAGE}" ]; then
	  kubectl set image "deployment/${CHALLENGE_NAME}" "healthcheck=$${PUSHED_HEALTHCHECK_IMAGE}"
	fi
endif

.gen/docker-image: challenge/Dockerfile .gen/src $(shell find challenge/files) ../kctf-conf/base/nsjail-docker/.gen/docker-image
	docker build -t "kctf-chal-${CHALLENGE_NAME}" challenge
	echo $$(docker image ls "kctf-chal-${CHALLENGE_NAME}" -q) > $@

.gen/kind-kubeconfig: .FORCE
	@command -v kind || (echo "error: kind not installed. Visit https://kind.sigs.k8s.io/" && false)
	kind get kubeconfig > $@

.gen/d4w-kubeconfig: .FORCE
	@command -v docker.exe || (echo "error: docker for windows not installed." && false)
	rm -f $@
	docker.exe context export default --kubeconfig $@

.gen/src: .FORCE
	$(MAKE) -C challenge/src ../../.gen/src

${CLUSTER_GEN}/image-tagged: .gen/docker-image | .cluster-config
	IMAGE_ID="$$(cat .gen/docker-image)"
	IMAGE_TAG="eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}:$${IMAGE_ID}"
	docker tag "kctf-chal-${CHALLENGE_NAME}" "$${IMAGE_TAG}"
	echo -n "$${IMAGE_TAG}" > $@

${CLUSTER_GEN}/image-pushed: ${CLUSTER_GEN}/image-tagged
	IMAGE_TAG="$$(cat ${CLUSTER_GEN}/image-tagged)"
	if [ "${PUSH_TARGET}" == "REMOTE" ]; then
	  docker push "$${IMAGE_TAG}"
	fi
	if [ "${PUSH_TARGET}" == "KIND" ]; then
	  kind load docker-image "$${IMAGE_TAG}"
	fi
	touch $@

.gen/healthcheck-docker-image: healthcheck/Dockerfile healthcheck/.gen/exploit.cpio.enc $(shell find healthcheck/files)
	docker build -t "kctf-healthcheck-${CHALLENGE_NAME}" healthcheck
	echo $$(docker image ls "kctf-healthcheck-${CHALLENGE_NAME}" -q) > $@

healthcheck/.gen/exploit.cpio.enc: healthcheck/.gen/exploit.cpio healthcheck/.gen/exploit.key
	openssl aes-256-cbc -e -in healthcheck/.gen/exploit.cpio -out $@ -K "$$(cat healthcheck/.gen/exploit.key)" -nosalt -iv 00000000000000000000000000000000

healthcheck/.gen/exploit.cpio: $(shell find healthcheck/exploit)
	pushd ${@D}
	rm -R exploit 2>/dev/null || true
	cp -R ../exploit .
	for f in $$(find exploit); do
	  TZ="UTC" touch -a -m -t 198001010000.00 $$f
	done
	rm exploit.cpio || true
	find exploit -print0 | sort -z | cpio -0 --reproducible -R 0:0 -o > exploit.cpio
	rm -R exploit
	popd

healthcheck/.gen/exploit.key: healthcheck/.gen/exploit.cpio
	sha256sum healthcheck/.gen/exploit.cpio | awk '{print $$1}' > $@

${CLUSTER_GEN}/healthcheck-image-tagged: .gen/healthcheck-docker-image | .cluster-config
	IMAGE_ID="$$(cat .gen/healthcheck-docker-image)"
	IMAGE_TAG="eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}-healthcheck:$${IMAGE_ID}"
	docker tag "kctf-healthcheck-${CHALLENGE_NAME}" "$${IMAGE_TAG}"
	echo -n "$${IMAGE_TAG}" > $@

${CLUSTER_GEN}/healthcheck-image-pushed: ${CLUSTER_GEN}/healthcheck-image-tagged
	IMAGE_TAG="$$(cat ${CLUSTER_GEN}/healthcheck-image-tagged)"
	if [ "${PUSH_TARGET}" == "REMOTE" ]; then
		docker push "$${IMAGE_TAG}"
	fi
	if [ "${PUSH_TARGET}" == "KIND" ]; then
		kind load docker-image "$${IMAGE_TAG}"
	fi
	touch $@

healthcheck/.gen/exploit-key.yaml: healthcheck/.gen/exploit.key | .cluster-config
	kubectl create secret generic "${CHALLENGE_NAME}-healthcheck-exploit-key" --from-file=exploit.key=healthcheck/.gen/exploit.key --dry-run -o yaml > $@

.healthcheck-exploit-key-secret: healthcheck/.gen/exploit-key.yaml | .cluster-config
	kubectl apply -f healthcheck/.gen/exploit-key.yaml

../kctf-conf/base/nsjail-docker/.gen/docker-image: .FORCE
	$(MAKE) -C ${@D}/.. .gen/docker-image

${CLUSTER_GEN}/remote-image: ${CLUSTER_GEN}/image-tagged .FORCE
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/image-tagged)"
	(kubectl get deployment/${CHALLENGE_NAME} -o jsonpath='{.spec.template.spec.containers[?(@.name == "challenge")].image}' 2>/dev/null || echo -n "$${PUSHED_IMAGE}") > $@

${CLUSTER_GEN}/remote-healthcheck-image: ${CLUSTER_GEN}/healthcheck-image-tagged .FORCE
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/healthcheck-image-tagged)"
	REMOTE_TAG=$$(kubectl get deployment/${CHALLENGE_NAME} -o jsonpath='{.spec.template.spec.containers[?(@.name == "healthcheck")].image}' 2>/dev/null || echo -n "$${PUSHED_IMAGE}")
	# if we previously deployed without a healthcheck, the output might be empty
	if [ -z "$${REMOTE_TAG}" ]; then
	  REMOTE_TAG="$${PUSHED_IMAGE}"
	fi
	echo -n "$${REMOTE_TAG}" > $@

.cluster-config:
	@if [ "${PROJECT}" = "CONFIGMISSING" ]; then
	@  echo 'error: cluster config not loaded. Run kctf-config-create or kctf-config-load'
	@  exit 1
	@fi
	kubectl config use-context "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}"
	mkdir -p ${CLUSTER_GEN}

.FORCE:

define DEPLOYMENT_KUSTOMIZATION_BASES
bases:
- ../../../challenge/config
- ../../../challenge/secrets
endef
define HEALTHCHECK_KUSTOMIZATION_BASES
- ../../../healthcheck/config
- ../../../healthcheck/secrets
endef

define DEPLOYMENT_KUSTOMIZATION
commonLabels:
  app: "$(CHALLENGE_NAME)"

patchesJson6902:
- target:
    group: "apps"
    version: "v1"
    kind: "Deployment"
    name: "chal"
  path: challenge_name.yaml
- target:
    group: "autoscaling"
    version: "v1"
    kind: "HorizontalPodAutoscaler"
    name: "chal"
  path: challenge_name.yaml

patchesStrategicMerge:
- containers.yaml
endef

define REPLACE_CHAL_NAME
- op: replace
  path: /metadata/name
  value: "$(CHALLENGE_NAME)"
endef

define CHAL_CONTAINERS
apiVersion: "apps/v1"
kind: "Deployment"
metadata:
  name: "chal"
spec:
  template:
    spec:
      volumes:
      - name: "secrets"
        secret:
          secretName: "$(CHALLENGE_NAME)-secrets"
      - name: "config"
        configMap:
          name: "$(CHALLENGE_NAME)-config"
endef
define HEALTHCHECK_CONTAINERS
      - name: "healthcheck-secrets"
        secret:
          secretName: "$(CHALLENGE_NAME)-healthcheck-secrets"
      - name: "healthcheck-exploit-key"
        secret:
          secretName: "$(CHALLENGE_NAME)-healthcheck-exploit-key"
      - name: "healthcheck-config"
        configMap:
          name: "$(CHALLENGE_NAME)-healthcheck-config"
endef

define NETWORK_KUSTOMIZATION
bases:
- ../../../../kctf-conf/base/k8s/network

commonLabels:
  app: "$(CHALLENGE_NAME)"

patchesJson6902:
- target:
    version: "v1"
    kind: "Service"
    name: "chal"
  path: challenge_name.yaml
endef

export DEPLOYMENT_KUSTOMIZATION
export DEPLOYMENT_KUSTOMIZATION_BASES
export HEALTHCHECK_KUSTOMIZATION_BASES
export REPLACE_CHAL_NAME
export CHAL_CONTAINERS
export NETWORK_KUSTOMIZATION
export HEALTHCHECK_CONTAINERS
# This target doesn't live in a cluster specific directory since we need the name to be predictable
# To make up for it, we FORCE execution every time
.gen/k8s: ${CLUSTER_GEN}/remote-image ${MAYBE_REMOTE_HEALTHCHECK_IMAGE} .FORCE | .cluster-config
	mkdir -p $@
	# deployment
	mkdir -p $@/deployment
	echo "$${REPLACE_CHAL_NAME}" > "$@/deployment/challenge_name.yaml"
	echo "$${DEPLOYMENT_KUSTOMIZATION_BASES}" > "$@/deployment/kustomization.yaml"
ifeq ($(HEALTHCHECK), true)
	echo "$${HEALTHCHECK_KUSTOMIZATION_BASES}" >> "$@/deployment/kustomization.yaml"
	echo "- ../../../../kctf-conf/base/k8s/deployment-with-healthcheck" >> "$@/deployment/kustomization.yaml"
else
	echo "- ../../../../kctf-conf/base/k8s/deployment" >> "$@/deployment/kustomization.yaml" 
endif
	CHAL_IMAGE="$$(cat ${CLUSTER_GEN}/remote-image)"
	CHAL_IMAGE=($${CHAL_IMAGE//:/ })
	echo -e "\nimages:\n- name: challenge\n  newName: $${CHAL_IMAGE[0]}\n  newTag: $${CHAL_IMAGE[1]}" >> "$@/deployment/kustomization.yaml"
ifeq ($(HEALTHCHECK), true)
	HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/remote-healthcheck-image)"
	HEALTHCHECK_IMAGE=($${HEALTHCHECK_IMAGE//:/ })
	echo -e "- name: healthcheck\n  newName: $${HEALTHCHECK_IMAGE[0]}\n  newTag: $${HEALTHCHECK_IMAGE[1]}" >> "$@/deployment/kustomization.yaml"
endif
	echo "$${DEPLOYMENT_KUSTOMIZATION}" >> "$@/deployment/kustomization.yaml"
	echo "$${CHAL_CONTAINERS}" > "$@/deployment/containers.yaml"
ifeq ($(HEALTHCHECK), true)
	echo "$${HEALTHCHECK_CONTAINERS}" >> "$@/deployment/containers.yaml"
endif
	# network
	mkdir -p $@/network
	echo "$${REPLACE_CHAL_NAME}" > "$@/network/challenge_name.yaml"
	echo "$${NETWORK_KUSTOMIZATION}" > "$@/network/kustomization.yaml"
	touch $@
