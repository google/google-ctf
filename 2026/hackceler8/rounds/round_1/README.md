# Hackceler8 2026

`skill.md` is the compiled Sega Genesis ROM file for the game. Run it in on MAME or your favourite emulator,
or flash it onto a cartridge to run it on a Sega Genesis console directly. Note that the org-provided scripted
input recording tools have been built for MAME.

To rebuild the rom, make your mods to the source files and run `make`. This will create your own `hx8.md` ROM.

On your first build this installs the toolchain which might take a while to compile.

Directory structure:
* `game/`: This is where the main game businesslogic lives.
* `resources/`: Graphics, tilesets, and maps.
* `plugins/`: MAME lua scripts for recording and replaying scripted input.
* `libs/megahx8`: Helper utilities for Sega Genesis APIs based on github.com/ricky26/rust-mega-drive
* `libs/convert`: Utility for converting the contents of `resources/` into source files to embed into the ROM
