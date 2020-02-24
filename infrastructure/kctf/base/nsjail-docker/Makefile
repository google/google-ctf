.PHONY: docker

docker: gen/docker-image

.gen/docker-image: Dockerfile $(shell find files)
	docker build -t "kctf-nsjail" .
	echo $$(docker image ls "kctf-nsjail" -q) > $@
