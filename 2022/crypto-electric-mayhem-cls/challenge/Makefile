all: firmware.tgz elmo.tgz traces.json.gz server.tgz

# Use tar to dereference the symlinks to third_party.
# https://stackoverflow.com/questions/31881904/docker-follow-symlink-outside-context
firmware.tgz: firmware/main.c firmware/Makefile firmware/firmware.ld firmware.dockerfile
	- docker rm tmp-firmware-container 2>/dev/null
	tar -czh . | docker build -t tmp-firmware-image -f firmware.dockerfile -
	docker run --name tmp-firmware-container tmp-firmware-image /bin/true
	docker cp tmp-firmware-container:/build/firmware.tgz .
	- docker rm tmp-firmware-container 2>/dev/null
	touch firmware.tgz

elmo.tgz: elmo.dockerfile
	- docker rm tmp-elmo-container 2>/dev/null
	tar -czh . | docker build -t tmp-elmo-image -f elmo.dockerfile -
	docker run --name tmp-elmo-container tmp-elmo-image /bin/true
	docker cp tmp-elmo-container:/build/elmo.tgz .
	- docker rm tmp-elmo-container 2>/dev/null
	touch elmo.tgz

traces.json.gz: flag firmware.tgz elmo.tgz traces/collect.py traces/downsample.py traces.dockerfile
	- docker rm tmp-traces-container 2>/dev/null
	tar -czh . | docker build -t tmp-traces-image -f traces.dockerfile -
	docker run --name tmp-traces-container tmp-traces-image /bin/true
	docker cp tmp-traces-container:/build/traces.json.gz .
	- docker rm tmp-traces-container 2>/dev/null
	touch traces.json.gz

server.tgz: web/server.go web.dockerfile
	- docker rm tmp-server-container 2>/dev/null
	docker build -t tmp-server-image -f web.dockerfile .
	docker run --name tmp-server-container tmp-server-image /bin/true
	docker cp tmp-server-container:/build/server.tgz .
	- docker rm tmp-server-container 2>/dev/null
	touch server.tgz

clean:
	rm firmware.tgz elmo.tgz traces.json.gz server.tgz
