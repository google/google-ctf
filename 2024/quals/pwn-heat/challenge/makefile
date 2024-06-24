all: d8 snapshot_blob.bin

d8 snapshot_blob.bin: build.dockerfile args.gn v8.patch
	- docker rm tmp-chal-container 2> /dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/v8/v8/out/x64.release/d8 .
	docker cp tmp-chal-container:/build/v8/v8/out/x64.release/snapshot_blob.bin .
	- docker rm tmp-chal-container 2> /dev/null
	touch d8 snapshot_blob.bin
