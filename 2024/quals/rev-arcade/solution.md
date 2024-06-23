# Challenge solution

Follow these steps to find the solution.

## Getting started

Download the challenge attaachment, it contains a `challenge.zip`. Unzip that and you get:

```
$ unzip -l challenge.zip 
Archive:  challenge.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    17587  2024-06-09 22:05   roms/gctf.zip
     4575  2024-06-09 22:05   roms/neogeo.zip
      172  2024-06-09 22:05   README
     2174  2024-06-09 22:11   hash/neogeo.xml
---------                     -------
    24508                     4 files

```

```
$ cat README
We found a dusty cartridge from an old arcade machine, how can we play it?

Run with MAME:

mame -hashpath hash -rp roms -nocoinlock -noautosave -skip_gameinfo neogeo gctf
```

Install MAME: https://www.mamedev.org/

`$ sudo apt install mame`

Run the game:

`$ mame -hashpath hash -rp roms -nocoinlock -noautosave -skip_gameinfo neogeo gctf`

The game shows "insert coin", press the mapped key to insert a coin. The message changes to "press start", press the start button. MAME has these keys mappend, press "tab" to change the mapping.

A game shows up, there are two chests. You move the robot to the chests and press "A", a message pops up saying "There's only trash in here!". The user has to dive into the m68k program ROM to find a branch that will show a different message, once triggered it shows a key value, but the sprite is hidden on the lines below.

# The key

The sprite says "You found the key" but the key material is hidden on the lines below, outside the screen. The user must RE the m68k program ROM to move the sprite in the video RAM so it shows up. Now the user has a key.

# Diving into ROM files.

A disassembly of the ROM files (or playing around with MAME debugger) will tell that there's a secret "admin panel" subroutine. You can either jump to that subroutine or input the Konami code for it (Up Up Down Down Left Right Left Right B A).

This admin panel shows tow inputs: a key and a plaintext (flag). There's a message that says "press start to decrypt". The user puts the key and presss start, a message that says "decrypting..." shows up and then a sound indicating error (low frequency beep). The user has to change the flag input to the correct one. The user must RE the Z80 code since here's where the decryption happens.

A deep dive into the Z80 code shows where the encrypted flag is, and a decryption process. The user might pick up that this is TEA, but modified. The constant is 0xDEADBEEF and there's one step that adds 1 to the result. After reversing this code the user can now decyrpt the flag.