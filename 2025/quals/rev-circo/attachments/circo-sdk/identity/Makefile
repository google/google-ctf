bin_targets=$(shell find . -name '*.bin.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)

.PHONY: clean all
all: $(bin_targets)

clean:
	rm -rf *.bin

%.bin: %.bin.asm
	nasm -f bin $^ -o $@
