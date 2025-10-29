# Color Game Boy challenge

This is a Game Boy cartridge for the Game Boy color ("cgb" as listed in MAME).

The game contains a VM inside that needs to be reversed.

## Development

Download and install [MAME](https://www.mamedev.org/):

```sh
$ sudo apt install mame
```

Download and extract [RGBDS](https://github.com/gbdev/rgbds/releases/latest):

```sh
$ wget https://github.com/gbdev/rgbds/releases/download/v0.9.2/rgbds-0.9.2-linux-x86_64.tar.xz
$ mkdir -p rgbds && tar -xvf rgbds-0.9.2-linux-x86_64.tar.xz -C rgbds
```

Run the game in debug mode (launches MAME with debug):

```sh
$ make debug
```

Run the game in challenge mode:

```sh
$ make game
```

Re-build the challenge:

```sh
$ make challenge
```

The challenge is now under `attachments/`.

## Checking if the challenge works

Run the game in MAME:

```sh
$ /usr/games/mame -hashpath hash -window -rp roms gbcolor gctf -debug
```

MAME boots up and waits for your action. Type the following to move the game until it boots and switches WRAM bank 1.

```
go $1b4
```

Press the Konami code: Up + Up + Down + Down + Left + Right + Left + Right + B + A

You're now in the flag panel. Now fill the flag with the plaintext bytes:

```
fill C052,40,$0b,$1c,$0e,$4A,$2b,$48,$10,$47,$26,$48,$28,$37,$16,$48,$14,$40,$23,$1a,$30,$2b,$16,$0f,$48,$25,$0f,$0a,$48,$2a,$3d,$39,$48,$47,$0a,$3d,$37,$44,$48,$37,$4c,$4B
```

You should hear a success melody.

## Solving the challenge

Dump the encrypted flag and key.

First we dump the palette key order, this is found at boot (so just when you boot the game).
It's 40 bytes ($28) and they define the palette key order to generate the key for encryption.

```
dump key_in_vram1,$02DC,$28,1,0,$28
```

Once the game boots (after the BaDing!) and switches to the WRAM bank 1 (a handy command is to type `go $1b4` in MAME debugger).
There dump the encrypted flag (also 40 bytes):

```
dump encrypted_flag,$51fa,$28,1,0,$28
```

Now run the Python script to decrypt the flag bytes with the associated palette order:

```sh
$ ./solution.py --decrypt --flag_bytes encrypted_flag --tile_palette_bytes key_in_vram1 
Flag bytes read from encrypted_flag: $1c $17 $c7 $11 $c0 $c6 $c5 $85 $a3 $57 $9d $f1 $b2 $ae $01 $51 $e0 $f5 $18 $b1 $af $7f $13 $32 $39 $eb $e6 $26 $96 $26 $8b $aa $1f $23 $00 $37 $86 $7a $8d $bc 
Tile palette bytes read from key_in_vram1: $07 $01 $00 $05 $04 $03 $06 $02 $07 $00 $01 $05 $03 $04 $02 $06 $00 $07 $05 $01 $03 $04 $06 $02 $07 $00 $05 $01 $03 $04 $02 $06 $07 $00 $01 $05 $03 $04 $02 $06 
Decrypting
Plaintext hex bytes: ['0b', '1c', '0e', '4a', '2b', '48', '10', '47', '26', '48', '28', '37', '16', '48', '14', '40', '23', '1a', '30', '2b', '16', '0f', '48', '25', '0f', '0a', '48', '2a', '3d', '39', '48', '47', '0a', '3d', '37', '44', '48', '37', '4c', '4b']
Plaintext mapped bytes: CTF{i_H@d_fuN_L3aRniNG_cGB_h0w_@B0u7_u?}
```
