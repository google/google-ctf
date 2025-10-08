# Hackceler8 2025

`hx8-handout.md` is the compiled Sega Genesis ROM file for the game. Run it in your favourite emulator or flash
it onto a cartridge to run it on a Sega Genesis console directly.

The game is made for 4 players using the EA multitap ("4-way-play") so we recommend finding an emulator that
supports it.

To rebuild the rom, make your mods to the source files and run `make`. This will create your own `hx8.md` ROM.

On your first build this installs the toolchain which might take a while to compile.

Directory structure:
* `game/`: This is where the main game businesslogic lives.
* `resources/`: Graphics, tilesets, and maps.
* `libs/megahx8`: Helper utilities for Sega Genesis APIs based on github.com/ricky26/rust-mega-drive
* `libs/convert`: Utility for converting the contents of `resources/` into source files to embed into the ROM
