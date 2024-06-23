.PHONY: all
all: bzImage rootfs.img

bzImage: kconfig build_kernel.dockerfile
	- docker rm tmp-kernel-container 2>/dev/null
	docker build -t tmp-kernel-image -f build_kernel.dockerfile .
	docker run --name tmp-kernel-container tmp-kernel-image /bin/true
	docker cp tmp-kernel-container:/build/linux/arch/x86/boot/bzImage .
	- docker rm tmp-kernel-container 2>/dev/null

rootfs.img: chal.cc chal.sh chal.service chal.target build_image.dockerfile
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build_image.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/rootfs.img .
	- docker rm tmp-chal-container 2>/dev/null
