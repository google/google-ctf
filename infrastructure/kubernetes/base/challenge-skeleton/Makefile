.PHONY: deploy docker expose cluster-config deploy-healthcheck

SHELL := bash
.ONESHELL:

PROJECT:=CONFIGMISSING
CLUSTER_NAME:=CONFIGMISSING
ZONE:=CONFIGMISSING
-include ~/.config/kctf/cluster.conf

CHALLENGE_NAME:=$(shell basename ${PWD})
IMAGE_NAME=eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}
HEALTHCHECK_IMAGE_NAME=eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}-healthcheck
CLUSTER_GEN=gen/${PROJECT}_${ZONE}_${CLUSTER_NAME}
DEPLOYMENT_CONF_DIR=${CLUSTER_GEN}/deployment-conf

docker: gen/docker-image

deploy: ${CLUSTER_GEN}/autoscaling ${CLUSTER_GEN}/deployment ${CLUSTER_GEN}/secrets ${CLUSTER_GEN}/config ${CLUSTER_GEN}/healthcheck-secrets ${CLUSTER_GEN}/healthcheck-exploit-key-secret ${CLUSTER_GEN}/healthcheck-config cluster-config

expose: ${CLUSTER_GEN}/network deploy cluster-config

${CLUSTER_GEN}/network: | cluster-config
	kubectl apply -f k8s/network.yaml
	touch $@

${CLUSTER_GEN}/autoscaling: k8s/autoscaling.yaml | cluster-config
	kubectl apply -f k8s/autoscaling.yaml
	touch $@

${CLUSTER_GEN}/deployment: ${DEPLOYMENT_CONF_DIR} ${CLUSTER_GEN}/image-pushed ${CLUSTER_GEN}/healthcheck-image-pushed k8s/containers.yaml | cluster-config
	kubectl get "deployments/${CHALLENGE_NAME}" >/dev/null 2>&1 && kubectl delete "deployments/${CHALLENGE_NAME}"
	kubectl create -k ${DEPLOYMENT_CONF_DIR}
	touch $@

${CLUSTER_GEN}/secrets: $(shell find secrets) | cluster-config
	kubectl apply -k secrets
	touch $@

${CLUSTER_GEN}/config: $(shell find config) | cluster-config
	kubectl apply -k config
	touch $@

gen/docker-image: Dockerfile $(shell find files) ../kctf-conf/base/nsjail-docker/gen/docker-image
	docker build -t "kctf-chal-${CHALLENGE_NAME}" .
	echo $$(docker image ls "kctf-chal-${CHALLENGE_NAME}" -q) > $@

${CLUSTER_GEN}/image-pushed: gen/docker-image | cluster-config
	docker tag "kctf-chal-${CHALLENGE_NAME}" "${IMAGE_NAME}"
	docker push "${IMAGE_NAME}"
	touch $@

gen/healthcheck-docker-image: healthcheck/Dockerfile healthcheck/gen/exploit.cpio.enc $(shell find healthcheck/files)
	docker build -t "kctf-healthcheck-${CHALLENGE_NAME}" healthcheck
	echo $$(docker image ls "kctf-healthcheck-${CHALLENGE_NAME}" -q) > $@

healthcheck/gen/exploit.cpio.enc: healthcheck/gen/exploit.cpio healthcheck/gen/exploit.key
	openssl aes-256-cbc -e -in healthcheck/gen/exploit.cpio -out $@ -K "$$(cat healthcheck/gen/exploit.key)" -nosalt -iv 00000000000000000000000000000000

healthcheck/gen/exploit.cpio: $(shell find healthcheck/exploit)
	pushd ${@D}
	- rm -R exploit 2>/dev/null
	cp -R ../exploit .
	for f in $$(find exploit); do
	  TZ="UTC" touch -a -m -t 198001010000.00 $$f
	done
	find exploit -print0 | sort -z | cpio -0 --reproducible -R 0:0 -o > exploit.cpio
	rm -R exploit
	popd

healthcheck/gen/exploit.key: healthcheck/gen/exploit.cpio
	sha256sum healthcheck/gen/exploit.cpio | awk '{print $$1}' > $@

${CLUSTER_GEN}/healthcheck-image-pushed: gen/healthcheck-docker-image | cluster-config
	docker tag "kctf-healthcheck-${CHALLENGE_NAME}" "${HEALTHCHECK_IMAGE_NAME}"
	docker push "${HEALTHCHECK_IMAGE_NAME}"
	touch $@

${CLUSTER_GEN}/healthcheck-exploit-key-secret: healthcheck/gen/exploit.key | cluster-config
	SECRET_NAME="${CHALLENGE_NAME}-healthcheck-exploit-key"
	RESOURCE="secrets/$${SECRET_NAME}"
	kubectl get "$${RESOURCE}" >/dev/null 2>&1 && kubectl delete "$${RESOURCE}"
	kubectl create secret generic "$${SECRET_NAME}" --from-file=exploit.key=healthcheck/gen/exploit.key
	touch $@

${CLUSTER_GEN}/healthcheck-secrets: $(shell find healthcheck/secrets) | cluster-config
	kubectl apply -k healthcheck/secrets
	touch $@

${CLUSTER_GEN}/healthcheck-config: $(shell find healthcheck/config) | cluster-config
	kubectl apply -k healthcheck/config
	touch $@

../kctf-conf/base/nsjail-docker/gen/docker-image: ../kctf-conf/base/nsjail-docker/Dockerfile $(shell find ../kctf-conf/base/nsjail-docker/files)
	make -C ${@D}/.. gen/docker-image

define CLUSTER_KUSTOMIZATION
bases:
- "../../../k8s"
patchesStrategicMerge:
- "update_image_name.yaml"
endef

define UPDATE_IMAGE_NAME
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
endef

export CLUSTER_KUSTOMIZATION
export UPDATE_IMAGE_NAME
${DEPLOYMENT_CONF_DIR}: | cluster-config
	mkdir -p "${DEPLOYMENT_CONF_DIR}"
	echo "$${CLUSTER_KUSTOMIZATION}" > "${DEPLOYMENT_CONF_DIR}/kustomization.yaml"
	echo "$${UPDATE_IMAGE_NAME}" > "${DEPLOYMENT_CONF_DIR}/update_image_name.yaml"

cluster-config:
	@if [ "${PROJECT}" = "CONFIGMISSING" ]; then
	@  echo 'error: config not loaded'
	@  exit 1
	@fi
	mkdir -p ${CLUSTER_GEN}
