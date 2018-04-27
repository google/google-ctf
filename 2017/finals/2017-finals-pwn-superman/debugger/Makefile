

all: build

%:
	cp ../build/out/"$@" .

build: superman qemu-arm close
	docker build -t challenge .

server: build
	docker run --rm -p 1337:1337 challenge \
		socat -x TCP4-LISTEN:1337,fork,reuseaddr,bind=0.0.0.0 EXEC:'./close ./qemu-arm -strace ./superman'

test: build
	docker run --rm challenge sh -c './qemu-arm ./superman < ./hello_world.payload'

clean:
	rm -f superman qemu-arm close

.PHONY: all build
