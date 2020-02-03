.PHONY: deploy docker expose cluster-config deploy-healthcheck network deployment autoscaling deploy-secrets deploy-config healthcheck-secrets healthcheck-exploit-key-secret healthcheck-config FORCE

SHELL := bash
.ONESHELL:

PROJECT:=CONFIGMISSING
CLUSTER_NAME:=CONFIGMISSING
ZONE:=CONFIGMISSING
-include ~/.config/kctf/cluster.conf

CHALLENGE_NAME:=$(shell basename ${PWD})
CLUSTER_GEN=gen/${PROJECT}_${ZONE}_${CLUSTER_NAME}
DEPLOYMENT_CONF_DIR=${CLUSTER_GEN}/deployment-conf

docker: gen/docker-image

deploy: autoscaling deployment deploy-secrets deploy-config healthcheck-secrets healthcheck-exploit-key-secret healthcheck-config cluster-config

expose: network deploy cluster-config

clean:
	- rm -R gen/*
	- rm -R healthcheck/gen/*

network: | cluster-config
	kubectl apply -f k8s/network.yaml

autoscaling: | cluster-config
	kubectl apply -f k8s/autoscaling.yaml

deployment: ${DEPLOYMENT_CONF_DIR} ${CLUSTER_GEN}/image-pushed ${CLUSTER_GEN}/remote-image ${CLUSTER_GEN}/healthcheck-image-pushed ${CLUSTER_GEN}/remote-healthcheck-image | cluster-config
	kubectl apply -k ${DEPLOYMENT_CONF_DIR}
	# update the challenge container if the image changed
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/image-pushed)"
	CHAL_IMAGE="$$(cat ${CLUSTER_GEN}/remote-image)"
	if [ $${CHAL_IMAGE} != $${PUSHED_IMAGE} ]; then
	  kubectl set image "deployment/${CHALLENGE_NAME}" "challenge=$${PUSHED_IMAGE}"
	fi
	# update the healthcheck container if the image changed
	PUSHED_HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/healthcheck-image-pushed)"
	HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/remote-healthcheck-image)"
	if [ $${HEALTHCHECK_IMAGE} != $${PUSHED_HEALTHCHECK_IMAGE} ]; then
	  kubectl set image "deployment/${CHALLENGE_NAME}" "healthcheck=$${HEALTHCHECK_IMAGE}"
	fi

deploy-secrets: $(shell find secrets) | cluster-config
	kubectl apply -k secrets

deploy-config: $(shell find config) | cluster-config
	kubectl apply -k config

gen/docker-image: Dockerfile $(shell find files) ../kctf-conf/base/nsjail-docker/gen/docker-image
	docker build -t "kctf-chal-${CHALLENGE_NAME}" .
	echo $$(docker image ls "kctf-chal-${CHALLENGE_NAME}" -q) > $@

${CLUSTER_GEN}/image-pushed: gen/docker-image | cluster-config
	IMAGE_ID="$$(cat gen/docker-image)"
	IMAGE_TAG="eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}:$${IMAGE_ID}"
	docker tag "kctf-chal-${CHALLENGE_NAME}" "$${IMAGE_TAG}"
	docker push "$${IMAGE_TAG}"
	echo -n "$${IMAGE_TAG}" > $@

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
	IMAGE_ID="$$(cat gen/healthcheck-docker-image)"
	IMAGE_TAG="eu.gcr.io/${PROJECT}/${CHALLENGE_NAME}-healthcheck"
	docker tag "kctf-healthcheck-${CHALLENGE_NAME}" "${IMAGE_TAG}"
	docker push "${IMAGE_TAG}"
	echo -n "$${IMAGE_TAG}" > $@

healthcheck/gen/exploit-key.yaml: healthcheck/gen/exploit.key | cluster-config
	kubectl create secret generic "${CHALLENGE_NAME}-healthcheck-exploit-key" --from-file=exploit.key=healthcheck/gen/exploit.key --dry-run -o yaml > $@

healthcheck-exploit-key-secret: healthcheck/gen/exploit-key.yaml | cluster-config
	kubectl apply -f healthcheck/gen/exploit-key.yaml

healthcheck-secrets: $(shell find healthcheck/secrets) | cluster-config
	kubectl apply -k healthcheck/secrets

healthcheck-config: $(shell find healthcheck/config) | cluster-config
	kubectl apply -k healthcheck/config

../kctf-conf/base/nsjail-docker/gen/docker-image: ../kctf-conf/base/nsjail-docker/Dockerfile $(shell find ../kctf-conf/base/nsjail-docker/files)
	make -C ${@D}/.. gen/docker-image

define CLUSTER_KUSTOMIZATION
bases:
- ../../../k8s
patchesStrategicMerge:
- update_image_name.yaml
endef

define UPDATE_IMAGE_NAME
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${CHALLENGE_NAME}
spec:
  template:
    spec:
      containers:
      - name: challenge
        image: CHAL_IMAGE_PLACEHOLDER
      - name: healthcheck
        image: HEALTHCHECK_IMAGE_PLACEHOLDER
endef

export CLUSTER_KUSTOMIZATION
export UPDATE_IMAGE_NAME
${DEPLOYMENT_CONF_DIR}: ${CLUSTER_GEN}/remote-image ${CLUSTER_GEN}/remote-healthcheck-image | cluster-config
	mkdir -p $@
	echo "$${CLUSTER_KUSTOMIZATION}" > "${DEPLOYMENT_CONF_DIR}/kustomization.yaml"
	CHAL_IMAGE="$$(cat ${CLUSTER_GEN}/remote-image)"
	HEALTHCHECK_IMAGE="$$(cat ${CLUSTER_GEN}/remote-healthcheck-image)"
	echo "$${UPDATE_IMAGE_NAME}" | sed "s#CHAL_IMAGE_PLACEHOLDER#$${CHAL_IMAGE}#" | sed "s#HEALTHCHECK_IMAGE_PLACEHOLDER#$${HEALTHCHECK_IMAGE}#" > "${DEPLOYMENT_CONF_DIR}/update_image_name.yaml"
	touch $@

${CLUSTER_GEN}/remote-image: ${CLUSTER_GEN}/image-pushed FORCE
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/image-pushed)"
	(kubectl get deployment/${CHALLENGE_NAME} -o jsonpath='{.spec.template.spec.containers[?(@.name == "challenge")].image}' 2>/dev/null || echo -n "$${PUSHED_IMAGE}") > $@

${CLUSTER_GEN}/remote-healthcheck-image: ${CLUSTER_GEN}/healthcheck-image-pushed FORCE
	PUSHED_IMAGE="$$(cat ${CLUSTER_GEN}/healthcheck-image-pushed)"
	(kubectl get deployment/${CHALLENGE_NAME} -o jsonpath='{.spec.template.spec.containers[?(@.name == "healthcheck")].image}' 2>/dev/null || echo -n "$${PUSHED_IMAGE}") > $@

cluster-config:
	@if [ "${PROJECT}" = "CONFIGMISSING" ]; then
	@  echo 'error: config not loaded'
	@  exit 1
	@fi
	mkdir -p ${CLUSTER_GEN}

FORCE:
