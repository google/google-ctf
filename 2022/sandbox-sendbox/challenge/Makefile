# Please use docker for building your challenges so that SREs can rebuild it
# if necessary without installing any dependencies.
chal: chal.cc build.dockerfile
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/chal .
	docker cp tmp-chal-container:/build/init .
	- docker rm tmp-chal-container 2>/dev/null
	touch chal
