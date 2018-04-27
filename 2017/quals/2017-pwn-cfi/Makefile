.PHONY: build
build: attachments/cfi attachments/cfi.c attachments/toolchain.tar.gz

attachments/cfi: challenge/cfi
	make -C challenge
	cp challenge/cfi attachments/

attachments/cfi.c: challenge/cfi.c
	cp challenge/cfi.c attachments/

attachments/toolchain.tar.gz: challenge/toolchain.release
	tar -C $< -cf $@ .
