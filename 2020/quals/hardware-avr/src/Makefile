.ONESHELL:

.PHONY: clean all run attachments

all: avr/code.hex simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf attachments

simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf:
	git clone https://github.com/buserror/simavr.git
	cd simavr
	git checkout ff689b67581604e2da31756fe37ecc1101ebe3dc
	git apply ../simavr_diff
	make

avr/code.hex: avr/code.c
	avr-gcc -Os -mmcu=atmega328p avr/code.c -o avr/code.elf
	avr-objcopy -O ihex avr/code.elf avr/code.hex

avr/code_server.hex: avr/code.c
	avr-gcc -Os -mmcu=atmega328p avr/code.c -o avr/code_server.elf -DPASS1=\"doNOTl4unch_missi1es!\" -DPASS2=\"Ya3HD0o9QIAXmdLSOgkgv3vYryxktFbSzp2OJRmvCQ\" -DFLAG=\"CTF{1nv1sibl3_sei_r4c3_c0ndi7i0n}\"
	avr-objcopy -O ihex avr/code_server.elf avr/code_server.hex

clean:
	rm avr/code.elf avr/code.hex avr/code_server.hex
	rm -rf simavr
	rm -rf ../attachments
	rm -rf ../bin

attachments: avr/code.hex simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf simavr_diff avr/code_server.hex Makefile_for_players
	mkdir -p ../attachments
	cp avr/code.hex ../attachments
	cp simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf ../attachments
	cp simavr_diff ../attachments
	cp avr/code.c ../attachments
	cp Makefile_for_players ../attachments/Makefile
	mkdir -p ../bin
	cp avr/code_server.hex ../bin
	cp simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf ../bin

run: all
	simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf avr/code_server.hex
