#
#
#
# THIS MAKEFILE IS USED CTF-WIDE. IF YOU MAKE CHANGES IT WILL APPLY TO ALL CHALLENGES.
#
#
#

.PHONY: start stop docker ip status logs ssh ssh-healthcheck port-forward test-docker test-kind test-d4w .test-local clean .deploy .maybe-expose .cluster-config .deployment .secrets .config .healthcheck-secrets .healthcheck-exploit-key-secret .healthcheck-config .FORCE

SHELL := bash
.ONESHELL:
.SHELLFLAGS = -e -c

PUSH_TARGET="REMOTE"

PROJECT:=CONFIGMISSING
CLUSTER_NAME:=CONFIGMISSING
ZONE:=CONFIGMISSING
-include $(HOME)/.config/kctf/cluster.conf
KUBECONFIG=$(HOME)/.config/kctf/kube.conf
export KUBECONFIG

CHALLENGE_NAME:=$(shell basename ${CURDIR})
CLUSTER_GEN=gen/${PROJECT}_${ZONE}_${CLUSTER_NAME}
DEPLOYMENT_CONF_DIR=${CLUSTER_GEN}/deployment-conf

docker: gen/docker-image

start:
	source chal.conf
	if [ $${DEPLOY} = "true" ]; then
	  $(MAKE) .deploy
	else
	  echo "skipping deployment: DEPLOY=\"$${DEPLOY}\""
	fi

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

ssh: .cluster-config
	kubectl exec deployment/${CHALLENGE_NAME} -c challenge -it /bin/bash

ssh-healthcheck: .cluster-config
	kubectl exec deployment/${CHALLENGE_NAME} -c healthcheck -it /bin/bash

port-forward: .cluster-config
	kubectl port-forward deployment/${CHALLENGE_NAME} :1337 &

test-docker: PUSH_TARGET="LOCAL_DOCKER"
test-docker: docker
	docker run -d -p 1337 --mount type=bind,source="$(CURDIR)"/config,target=/config --mount type=bind,source="$(CURDIR)"/secrets,target=/secrets --privileged -it "kctf-chal-${CHALLENGE_NAME}"
	docker ps -f ancestor=kctf-chal-${CHALLENGE_NAME}

test-kind: LOCAL_KUBECONFIG="gen/kind-kubeconfig"
test-kind: PUSH_TARGET="KIND"
test-kind: | gen/kind-kubeconfig .test-local

test-d4w: LOCAL_KUBECONFIG="gen/d4w-kubeconfig"
test-d4w: PUSH_TARGET="LOCAL_DOCKER"
test-d4w: | gen/d4w-kubeconfig .test-local

.test-local: PROJECT="kctf-testing"
.test-local:
	kubectl config rename-context "$(shell kubectl config current-context --kubeconfig="${LOCAL_KUBECONFIG}")" "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}" --kubeconfig="${LOCAL_KUBECONFIG}" || true
	$(MAKE) .deploy PUSH_TARGET=${PUSH_TARGET} PROJECT=${PROJECT} ZONE=${ZONE} CLUSTER_NAME=${CLUSTER_NAME} KUBECONFIG="${LOCAL_KUBECONFIG}"
	kubectl patch deployment ${CHALLENGE_NAME}  --type json -p='[{"op": "remove", "path": "/spec/template/metadata/annotations/container.apparmor.security.beta.kubernetes.io~1challenge"}]' --kubeconfig=${LOCAL_KUBECONFIG}

clean:
	rm -R gen/* || true
	rm -R healthcheck/gen/* || true

.deploy: .deployment .secrets .config .healthcheck-secrets .healthcheck-exploit-key-secret .healthcheck-config .cluster-config .maybe-expose

.maybe-expose: | .cluster-config
	source chal.conf
	if [ "$${PUBLIC}" = "true" ]; then
	  kubectl apply -k k8s/network
	else
	  kubectl get "service/${CHALLENGE_NAME}" >/dev/null 2>&1 && kubectl delete "service/${CHALLENGE_NAME}" || true
	fi

.deployment: ${DEPLOYMENT_CONF_DIR} ${CLUSTER_GEN}/image-pushed ${CLUSTER_GEN}/remote-image ${CLUSTER_GEN}/healthcheck-image-pushed ${CLUSTER_GEN}/remote-healthcheck-image | .cluster-config
	kubectl apply -k ${DEPLOYMENT_CONF_DIR}
	# update the challenge container if the image changed
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/image-tagged)"
	CHAL_IMAGE="$$(cat ${CLUSTER_GEN}/remote-image)"
	if [ $${CHAL_IMAGE} != $${PUSHED_IMAGE} ]; then
	  kubectl set image "deployment/${CHALLENGE_NAME}" "challenge=$${PUSHED_IMAGE}"
	fi
	# update the healthcheck container if the image changed
	PUSHED_HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/healthcheck-image-tagged)"
	HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/remote-healthcheck-image)"
	if [ $${HEALTHCHECK_IMAGE} != $${PUSHED_HEALTHCHECK_IMAGE} ]; then
	  kubectl set image "deployment/${CHALLENGE_NAME}" "healthcheck=$${HEALTHCHECK_IMAGE}"
	fi

.secrets: $(shell find secrets) | .cluster-config
	kubectl apply -k secrets

.config: $(shell find config) | .cluster-config
	kubectl apply -k config

gen/docker-image: Dockerfile files gen/src $(shell find files) $(shell find secrets) $(shell find config) ../kctf-conf/base/nsjail-docker/gen/docker-image
	docker build -t "kctf-chal-${CHALLENGE_NAME}" .
	echo $$(docker image ls "kctf-chal-${CHALLENGE_NAME}" -q) > $@

gen/kind-kubeconfig: .FORCE
	@command -v kind || (echo "error: kind not installed. Visit https://kind.sigs.k8s.io/" && false)
	kind get kubeconfig > $@

gen/d4w-kubeconfig: .FORCE
	@command -v docker.exe || (echo "error: docker for windows not installed." && false)
	rm -f $@
	docker.exe context export default --kubeconfig $@

gen/src: .FORCE
	$(MAKE) -C src ../gen/src

${CLUSTER_GEN}/image-tagged: gen/docker-image | .cluster-config
	IMAGE_ID="$$(cat gen/docker-image)"
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
	# LOCAL_DOCKER doesn't need to be pushed
	touch $@

gen/healthcheck-docker-image: healthcheck/Dockerfile healthcheck/gen/exploit.cpio.enc $(shell find healthcheck/files)
	docker build -t "kctf-healthcheck-${CHALLENGE_NAME}" healthcheck
	echo $$(docker image ls "kctf-healthcheck-${CHALLENGE_NAME}" -q) > $@

healthcheck/gen/exploit.cpio.enc: healthcheck/gen/exploit.cpio healthcheck/gen/exploit.key
	openssl aes-256-cbc -e -in healthcheck/gen/exploit.cpio -out $@ -K "$$(cat healthcheck/gen/exploit.key)" -nosalt -iv 00000000000000000000000000000000

healthcheck/gen/exploit.cpio: $(shell find healthcheck/exploit)
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

healthcheck/gen/exploit.key: healthcheck/gen/exploit.cpio
	sha256sum healthcheck/gen/exploit.cpio | awk '{print $$1}' > $@

${CLUSTER_GEN}/healthcheck-image-tagged: gen/healthcheck-docker-image | .cluster-config
	IMAGE_ID="$$(cat gen/healthcheck-docker-image)"
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

healthcheck/gen/exploit-key.yaml: healthcheck/gen/exploit.key | .cluster-config
	kubectl create secret generic "${CHALLENGE_NAME}-healthcheck-exploit-key" --from-file=exploit.key=healthcheck/gen/exploit.key --dry-run -o yaml > $@

.healthcheck-exploit-key-secret: healthcheck/gen/exploit-key.yaml | .cluster-config
	kubectl apply -f healthcheck/gen/exploit-key.yaml

.healthcheck-secrets: $(shell find healthcheck/secrets) | .cluster-config
	kubectl apply -k healthcheck/secrets

.healthcheck-config: $(shell find healthcheck/config) | .cluster-config
	kubectl apply -k healthcheck/config

../kctf-conf/base/nsjail-docker/gen/docker-image: .FORCE
	$(MAKE) -C ${@D}/.. gen/docker-image

define CLUSTER_KUSTOMIZATION
bases:
- ../../../k8s/deployment
patchesStrategicMerge:
- update_image_name.yaml
endef

define UPDATE_IMAGE_NAME
apiVersion: apps/v1
kind: Deployment
metadata:
  name: chal
spec:
  template:
    spec:
      containers:
      - name: challenge
        image: CHAL_IMAGE_PLACEHOLDER
        imagePullPolicy: IfNotPresent
      - name: healthcheck
        image: HEALTHCHECK_IMAGE_PLACEHOLDER
        imagePullPolicy: IfNotPresent
endef

export CLUSTER_KUSTOMIZATION
export UPDATE_IMAGE_NAME
${DEPLOYMENT_CONF_DIR}: ${CLUSTER_GEN}/remote-image ${CLUSTER_GEN}/remote-healthcheck-image | .cluster-config
	mkdir -p $@
	echo "$${CLUSTER_KUSTOMIZATION}" > "${DEPLOYMENT_CONF_DIR}/kustomization.yaml"
	CHAL_IMAGE="$$(cat ${CLUSTER_GEN}/remote-image)"
	HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/remote-healthcheck-image)"
	echo "$${UPDATE_IMAGE_NAME}" | sed "s#CHAL_IMAGE_PLACEHOLDER#$${CHAL_IMAGE}#" | sed "s#HEALTHCHECK_IMAGE_PLACEHOLDER#$${HEALTHCHECK_IMAGE}#" > "${DEPLOYMENT_CONF_DIR}/update_image_name.yaml"
	touch $@

${CLUSTER_GEN}/remote-image: ${CLUSTER_GEN}/image-tagged .FORCE
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/image-tagged)"
	(kubectl get deployment/${CHALLENGE_NAME} -o jsonpath='{.spec.template.spec.containers[?(@.name == "challenge")].image}' 2>/dev/null || echo -n "$${PUSHED_IMAGE}") > $@

${CLUSTER_GEN}/remote-healthcheck-image: ${CLUSTER_GEN}/healthcheck-image-tagged .FORCE
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/healthcheck-image-tagged)"
	(kubectl get deployment/${CHALLENGE_NAME} -o jsonpath='{.spec.template.spec.containers[?(@.name == "healthcheck")].image}' 2>/dev/null || echo -n "$${PUSHED_IMAGE}") > $@

.cluster-config:
	@if [ "${PROJECT}" = "CONFIGMISSING" ]; then
	@  echo 'error: cluster config not loaded. Run kctf-config-create or kctf-config-load'
	@  exit 1
	@fi
	kubectl config use-context "kctf_${PROJECT}_${ZONE}_${CLUSTER_NAME}"
	mkdir -p ${CLUSTER_GEN}

.FORCE:
