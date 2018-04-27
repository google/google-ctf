MCU = attiny88
MCU_FLASH = t88
CC = avr-g++
CFLAGS = -DF_CPU=8000000 -mmcu=$(MCU) -Os -flto -std=c++14 -DI2C_USE_HIGHSPEED -g -Wall

# One of: {DEV=0, SLOT=1, POKER_RED=2, POKER_GREEN=3, POKER_GREEN but with non-twisted wires=4}
MODEL = 3

SOURCES = main.cpp ILI9225.cpp dac.cpp i2c.cpp spi.cpp input.cpp gui.cpp rng.cpp game.cpp item.cpp assets.cpp
ASSETS = assets/seven_2c.h assets/bar_2c.h assets/lemon_3c.h assets/bg_column.h assets/bg_jackpot.h assets/bg_star.h assets/bg_top_bar.h


all: main.ihex

# Conversion png -> h
.SUFFIXES: .png .h

.png.h:
	python3 assets/png_to_c.py $< $@

main: $(SOURCES) Makefile $(ASSETS)
	$(CC) $(CFLAGS) -DMODEL=$(MODEL) -o $@ $(SOURCES)

main.ihex: main
	avr-objcopy -j .text -j .data -O ihex $< $@

flash: main.ihex size
	sudo avrdude -p $(MCU_FLASH) -c usbasp -U flash:w:$<

fuses:
	sudo avrdude -p $(MCU_FLASH) -c usbasp -U lfuse:w:0xEE:m -U hfuse:w:0xDF:m -U efuse:w:0xFF:m

size: main
	avr-nm --size-sort -C -r $<
	avr-size -C --mcu=$(MCU) $<

clean:
	rm -f main.ihex main $(ASSETS)

.PHONY: flash fuses clean size
