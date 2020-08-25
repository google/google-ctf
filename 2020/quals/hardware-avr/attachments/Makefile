.ONESHELL:

.PHONY: clean all run

all: code.hex simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf

simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf:
	git clone https://github.com/buserror/simavr.git
	cd simavr
	git checkout ff689b67581604e2da31756fe37ecc1101ebe3dc
	git apply simavr_diff
	make

code.hex: code.c
	avr-gcc -Os -mmcu=atmega328p code.c -o code.elf
	avr-objcopy -O ihex code.elf code.hex

run: all
	simavr/examples/board_simduino/obj-x86_64-linux-gnu/simduino.elf code.hex
