# Mega Sonk in MegaRust

To run the game:

```
mame genesis -cart sonk.md
```

Record your solution and send it up to the server to get the flag! Make sure your recording is at most 5 minutes long.

```
mame genesis -cart sonk.md -record solution.inp
python3 submit.py /home/user/.mame/inp/solution.inp mega.2025.ctfcompetition.com 1337
```

To rebuild the game:

```
make sonk.md
```

On the first run this builds the compilation toolchain which could take up to half an hour.

Rebuild and run the game:

```
 make run
```


## Credits

Compilation toolchain based on
* https://github.com/ricky26/rust-mega-drive
* https://github.com/rust-lang/rustc_codegen_gcc

Graphics credits:
* https://opengameart.org/content/8-color-full-game-sprite-tiles
* https://opengameart.org/content/plastic-shamtastic
* https://opengameart.org/content/wasp-0
