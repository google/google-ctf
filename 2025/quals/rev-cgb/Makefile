# Location of MAME.
MAME?=/usr/games/mame

# Location of RGBDS
RGBASM?=rgbds/rgbasm
RGBLINK?=rgbds/rgblink
RGBFIX?=rgbds/rgbfix
RGBFX?=rgbds/rgbfx

# Game ROM name.
GAMENAME?=gctf


##### GAME #####
#
# The actual game cartridge, this contains the challenge.

ASM_FILES = $(wildcard src/rom/*.asm)

OBJ_FILES = $(patsubst src/rom/%.asm, src/rom/%.o, $(ASM_FILES))

src/rom/%.o: src/rom/%.asm
	$(RGBASM) -o $@ $<

rom: $(OBJ_FILES) | roms
	$(RGBLINK) -o roms/$(GAMENAME)/$(GAMENAME).gb $(OBJ_FILES)

##### BOOT ROM #####
#
# Game Boy Color's boot ROM is broken in two parts: https://gbdev.io/pandocs/Power_Up_Sequence.html#color-models-cgb0-cgb-agb0-agb
# The first part goes from $0000 - $0100 (exclusive) and the second part goes from
# $0200 - $0900 (exclusive). The cartridge's header (and some other things) are loaded at $0100 - $0150 (exclusive),
# and the game starts at $0150 ¯\_(ツ)_/¯.

# The first part of the boot rom.
src/boot/gbc_boot.1: src/boot/gbc_boot.1.asm
	$(RGBASM) -o $@.o $<
	$(RGBLINK) -x -o $@ $@.o

# The second part of the boot rom.
src/boot/gbc_boot.2: src/boot/gbc_boot.2.asm
	$(RGBASM) -o $@.o $<
	$(RGBLINK) -x -o $@ $@.o
# Remove the padding of $0200 introduced by RGBLink.
# TODO(nvidela): I think we can skip this if we make the section start at $0000.
	dd if=$@ of=$@ bs=1 skip=512 conv=notrunc

# The boot ROM for the Color Game Boy, we use a custom one.
# We need to create roms/gbcolor because that's where MAME expects the boot ROM images
# to be found for cgb ¯\_(ツ)_/¯.
boot: src/boot/gbc_boot.1 src/boot/gbc_boot.2 | roms
	mkdir -p roms/gbcolor
	cp $^ roms/gbcolor

# ROMs folder, to hold all the compiled ROMs.
roms:
	mkdir -p roms roms/$(GAMENAME)

# Run the challenge.
run: rom boot | roms
	$(MAME) -hashpath hash -window -rp roms gbcolor $(GAMENAME)

# Run the challenge in debug mode.
debug: rom boot | roms
	$(MAME) -hashpath hash -window -rp roms gbcolor $(GAMENAME) -debug

# Make the challenge for production.
challenge: rom boot | roms hash attachments
	cp -r roms hash attachments
