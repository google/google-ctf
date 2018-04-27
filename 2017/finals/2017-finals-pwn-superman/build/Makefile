
all:
	docker build -t superman-build .
	docker run --rm -v $(PWD):/shared superman-build \
		sh /shared/src/build.sh

test:
	docker run --rm -v $(PWD):/shared superman-build \
		sh -c 'cd /shared/; out/close out/qemu-arm out/superman < ./hello_world.payload'

.PHONY: all build
