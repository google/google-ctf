chal: chal.c

bzImage: build_kernel.dockerfile kconcat_module/kconcat.c
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build_kernel.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/linux/arch/x86/boot/bzImage .
	docker cp tmp-chal-container:/build/linux/vmlinux .
	docker cp tmp-chal-container:/build/linux/.config .
	docker cp tmp-chal-container:/build/kconcat_module/kconcat.ko .
	zip vmlinux.zip vmlinux

rootfs.img: build_image.dockerfile init kconcat.ko bzImage
	- docker rm tmp-chal-image-container 2>/dev/null
	- mkdir rootfs
	# Build the root filesystem of the VM as a container image,
	# then export the contents and put them in an ext4 disk
	docker build -t tmp-chal-image -f build_image.dockerfile .
	docker create --name tmp-chal-image-container tmp-chal-image
	docker export tmp-chal-image-container > rootfs.tar
	- docker rm tmp-chal-container 2>/dev/null
	dd if=/dev/zero of=rootfs.img bs=1G count=3
	sudo mkfs.ext4 -F rootfs.img
	sudo mount -o loop rootfs.img rootfs/
	sudo tar -xf rootfs.tar -C rootfs/
	- rm rootfs.tar
	sudo umount rootfs/
	- rm rootfs.img.zip
	zip rootfs.img.zip rootfs.img