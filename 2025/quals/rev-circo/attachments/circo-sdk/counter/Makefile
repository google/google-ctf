bin_targets=$(shell find . -name '*.bin.asm' -type f -printf "%f\n" | sed 's/\.asm//' | xargs)

.PHONY: clean all
all: $(bin_targets)

clean:
	rm -rf *.bin

%.bin: %.bin.asm
	nasm -f bin $^ -o $@

program.json: program.ys program.sv
	yosys -s program.ys

program.bin.asm: program.jq program.json
	jq -r -f program.jq program.json > program.bin.asm
