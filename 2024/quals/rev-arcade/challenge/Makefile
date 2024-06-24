# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# MAME config
GAMEID?=gctf
GAMENAME?=gctf

# ROM file names, this is how MAME likes it.
MROM?=roms/$(GAMEID)-m1.m1
VROM?=roms/$(GAMEID)-v1.v1
CROM1?=roms/$(GAMEID)-c1.c1
CROM2?=roms/$(GAMEID)-c2.c2
SROM?=roms/$(GAMEID)-s1.s1
PROM?=roms/$(GAMEID)-p1.p1

# BIOS file names
SM1?=roms/sm1.sm1
LO?=roms/000-lo.lo
SFIX?=roms/sfix.sfix
SP?=roms/sp-s2.sp1

# Tools from ngdevkit, to make the assets for the game.
TILETOOL?=../../third_party/rev-arcade/ngdevkit/tiletool.py

# Binutils
SOX?=sox
TRUNCATE?=truncate

# Sprite samples
# Order is important! Don't change the order!
# This order is referenced in the code.
SPRITES=logo background chest robot trashmsg key distraction1 distraction2

# This builds everything, the game and the BIOS.
all: roms/$(GAMENAME).zip roms/neogeo.zip | roms

# This zips all the ROM files for the game.
roms/$(GAMENAME).zip: $(PROM) $(VROM) $(MROM) $(CROM1) $(CROM2) $(SROM) | roms
	zip -j -u $@ $^

# NeoGeo minimal BIOS.
roms/neogeo.zip: $(SP) $(SFIX) $(LO) $(SM1) | roms
	zip -j -u $@ $^

# Create roms directory.
roms:
	mkdir -p roms

#########
# V ROM #
#########

# V ROM is used for sound. All the sound samples are stored here as ADPCMA files.
# Since the challenge doesn't have audio files, fill this with zeros.
VROMSIZE=524288
$(VROM): | roms
	echo "Thank you user, but our Princess is in another castle" > $@
	objcopy -I binary -O binary -S --gap-fill 0x00 --pad-to $(VROMSIZE) $@ $@

#########
# M ROM #
# #######

# Z80 driver for receiving m68k commands and communicating with the YM2610.
MROMSIZE:=131072
$(MROM): | src/z80/main.asm roms
	vasmz80 -Fbin -o $@ src/z80/main.asm
	objcopy -I binary -O binary -S --gap-fill 0xff --pad-to $(MROMSIZE) $@ $@

#########
# S ROM #
#########

# Fix map used to display tiles (8x8 pixels) on the fix layer.
$(SROM): | fix_map/GoogleFixLayer.bmp roms
	$(TILETOOL) --fix -o $@ -v -c fix_map/GoogleFixLayer.bmp

#########
# C ROM #
#########

# Sprites converted to the weird format that NeoGeo wants.
# C1 contains the even bytes, and C2 contains the odd bytes.
roms/%.c1 roms/%.c2: sprites/%.gif | sprites
	$(TILETOOL) --sprite -c $< -o $@ $(@:%.c1=%).c2

CROMSIZE:=1048576
$(CROM1): $(SPRITES:%=roms/%.c1) | roms
	cat $^ > $@ && $(TRUNCATE) -s $(CROMSIZE) $@

$(CROM2): $(SPRITES:%=roms/%.c2) | roms
	cat $^ > $@ && $(TRUNCATE) -s $(CROMSIZE) $@

#########
# P ROM #
#########

# M68k code that is the core of the game logic.
PROMSIZE:=524288
$(PROM): | src/cartridge/main.asm roms /usr/bin/vasmm68k_mot /usr/bin/m68k-linux-gnu-objcopy
	vasmm68k_mot -no-opt -Fbin -o $@ src/cartridge/main.asm 
	m68k-linux-gnu-objcopy -I binary -O binary -S --gap-fill 0xff --pad-to $(PROMSIZE) $@ $@
	dd if=$@ of=$@ conv=notrunc,swab

###############
# NeoGeo BIOS #
###############

# Empty Graphic ROM, we don't need it.
# This is the Fix map when no cartridge is inserted.
SFIXSIZE=131072
$(SFIX): | roms
	echo "All your strings are belong to us" > $@
	objcopy -I binary -O binary -S --gap-fill 0x00 --pad-to $(SFIXSIZE) $@ $@

# Zoom ROM, this tells the program ROM how to scale the sprites.
# Given we only have sprites that are max size or 0 size, we created a handy Python script
# to fill up this ROM with a 0 level (just print $ff sprite line) and all the other levels will print
# all sprites lines (from $00 -> $ff).
$(LO): | roms
	zoom_rom/create_zoom.py -o $@



# The default sound driver when no cartridge is inserted.
# We don't care about this for the challenge, so just put a generic ROM that hangs. If the M68k sends a byte through REG_SOUND
# to this driver, it'll ignore it and continue hanging.
SM1SIZE=65536
$(SM1): src/bios/sm1.asm | roms
	vasmz80 -Fbin -o $@ $<
	objcopy -I binary -O binary -S --gap-fill 0xff --pad-to $(SM1SIZE) $@ $@

# The BIOS ROM.
# This is a very minimal and custom BIOS for NeoGeo games.
# It should not be used outside of this challenge, there's a lot of unimplemented features.
SPSIZE:=524288
$(SP): src/bios/main.asm | roms /usr/bin/vasmm68k_mot /usr/bin/m68k-linux-gnu-objcopy
	vasmm68k_mot -no-opt -Fbin -o $@ $<
	m68k-linux-gnu-objcopy -I binary -O binary -S --gap-fill 0xff --pad-to $(SPSIZE) $@ $@
	dd if=$@ of=$@ conv=notrunc,swab

# Run the game with MAME, for debugging purposes.
run: all
	/usr/games/mame -debug -hashpath hash -nocoinlock -w -resolution0 2000x2000 -noautosave -skip_gameinfo -update_in_pause -rp roms neogeo $(GAMENAME)

# Make the challenge and package it like users should receive it.
challenge: all | instructions
	cp instructions ../attachments/README
	cp roms/$(GAMENAME).zip ../attachments/roms
	cp roms/neogeo.zip ../attachments/roms
	cp hash/neogeo.xml ../attachments/hash

# Clean everything we built.
clean:
	rm -rf *.o roms/* samples/* challenge.zip
