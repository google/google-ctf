#!/usr/bin/python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import os
import argparse

from typing import Tuple

# Palette data is stored in the boot ROM file, loaded into the system
# and the boot ROM is erased away.
# We use it as a constant here but you can drump these byes by reading from the boot ROM.
# This dictoinary has the key as the palette number and the value as the color bytes stored for that palette.
# Palettes in GameBoy Color are stored byte by byte, and retrieved the same way.
palette_data_dict = {
    0: ['ff', 'ff', '03', '1c', '37', '5b', '00', '00'],
    1: ['ff', 'ff', '7f', '42', '3d', '0a', '00', '00'],
    2: ['ff', 'ff', '76', '5b', '61', '1c', '00', '00'],
    3: ['ff', 'ff', '2e', '79', '64', '11', '00', '00'],
    4: ['ff', 'ff', '40', '33', '58', '35', '00', '00'],
    5: ['ff', 'ff', '7a', '7d', '4c', '22', '00', '00'],
    6: ['ff', 'ff', '0f', '4a', '56', '65', '00', '00'],
    7: ['ff', 'ff', '13', '78', 'f7', '69', '00', '00']
}

# These mappings are in rom_bank1, it's the tiles in VRAM0.
# The tile information is stored in the ROM, it's complicated to extract via `dump` so
# we just add the hardcoded mappings here.
char_mapping = {
    # Uppercase Letters
    "09": "A", "0a": "B", "0b": "C", "0c": "D", "0d": "E", "0e": "F", "0f": "G",
    "10": "H", "11": "I", "12": "J", "13": "K", "14": "L", "15": "M", "16": "N",
    "17": "O", "18": "P", "19": "Q", "1a": "R", "1b": "S", "1c": "T", "1d": "U",
    "1e": "V", "1f": "W", "20": "X", "21": "Y", "22": "Z",
    "23": "a", "24": "b", "25": "c", "26": "d", "27": "e", "28": "f", "29": "g",
    "2a": "h", "2b": "i", "2c": "j", "2d": "k", "2e": "l", "2f": "m", "30": "n",
    "31": "o", "32": "p", "33": "q", "34": "r", "35": "s", "36": "t", "37": "u",
    "38": "v", "39": "w", "3a": "x", "3b": "y", "3c": "z",
    "3d": "0", "3e": "1", "3f": "2", "40": "3", "41": "4", "42": "5",
    "43": "6", "44": "7", "45": "8", "46": "9",
    "47": "@", "48": "_", "49": "-", "4a": "{", "4b": "}", "4c": "?",
}

flag_bytes = [

]

def main():
    parser = argparse.ArgumentParser(
        description="Challenge solution helper.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--decrypt",
        action="store_true",
        help="Set the operation mode to decryption. Mutually exclusive with --encrypt."
    )
    mode_group.add_argument(
        "--encrypt",
        action="store_true",
        help="Set the operation mode to encryption. Mutually exclusive with --decrypt."
    )

    parser.add_argument(
        "--flag_bytes",
        type=str,
        required=True,
        help="Path to the flag bytes file."
    )
    parser.add_argument(
        "--tile_palette_bytes",
        type=str,
        required=True,
        help="Path to the tile palette bytes file."
    )

    args = parser.parse_args()

    if not os.path.exists(args.flag_bytes):
        parser.error(f"Error: Flag bytes file not found at '{args.flag_bytes}'")
    if not os.path.exists(args.tile_palette_bytes):
        parser.error(f"Error: Tile palette bytes file not found at '{args.tile_palette_bytes}'")

    flag_bytes = []
    # Read the string bytes and convert them to an array of bytes.
    with open(args.flag_bytes, 'r') as f:
        string_bytes = f.read().strip('\n').rstrip()[7:].split(" ")
        flag_bytes = bytes([int(h, 16) for h in string_bytes])
    
    print("Flag bytes read from %s: %s" % (args.flag_bytes, ''.join(f'${b:02x} ' for b in flag_bytes)))

    key_in_vram1_bytes = []
    with open(args.tile_palette_bytes, 'r') as f:
        string_bytes = f.read().strip('\n')[7:].split(" ")
        key_in_vram1_bytes = bytes([int(h, 16) for h in string_bytes])

    print("Tile palette bytes read from %s: %s" % (args.tile_palette_bytes, ''.join(f'${b:02x} ' for b in key_in_vram1_bytes)))

    if args.decrypt:
        print("Decrypting")
        do_decrypt(flag_bytes, key_in_vram1_bytes)
    elif args.encrypt:
        print("Encrypting")
        do_encrypt(flag_bytes, key_in_vram1_bytes)
    else:
        sys.exit(1)


def do_encrypt(plaintext_flag_bytes: list, key_in_vram1_bytes: list) -> list:
    print("Plaintext mapped bytes: %s" % map_bytes(plaintext_flag_bytes))
    encrypted_bytes = encrypt(plaintext_flag_bytes, key_in_vram1_bytes)
    print("Encrypted bytes: %s" % ', '.join(f'${b:02x}' for b in encrypted_bytes))


def do_decrypt(encrypted_flag_bytes: list, key_in_vram1_bytes: list) -> list:
    plaintext_bytes = decrypt(encrypted_flag_bytes, key_in_vram1_bytes)
    print("Plaintext hex bytes: %s" % [f'{b:02x}' for b in plaintext_bytes])
    print("Plaintext mapped bytes: %s" % map_bytes(plaintext_bytes))


def map_bytes(plaintext_bytes: list) -> list:
    plaintext_string = ""
    for b in plaintext_bytes:
        try:
            b = char_mapping[f'{b:02x}']
        except KeyError:
            print("Mapping not found for byte $%s, this means this plaintext byte is wrong. Replacing with # to indicate that." % b)
            b = "#"
        finally:
            plaintext_string += b
    return plaintext_string


def encrypt(encrypted_flag_bytes, key_in_vram1_bytes) -> list:
    # Generate the key. This comes from the palette and bytes in VRAM1.
    key = generate_key(key_in_vram1_bytes)
    return do_feistel_algorithm(encrypted_flag_bytes, key)


def decrypt(encrypted_flag_bytes, key_in_vram1_bytes) -> list:
    # Generate the key. This comes from the palette and bytes in VRAM1.
    key = generate_key(key_in_vram1_bytes)
    for i in range(len(key)):
        key[i].reverse()
    return do_feistel_algorithm(encrypted_flag_bytes, key, True)


# Decrypts the encrypted flag with the given key stored in VRAM1.
def do_feistel_algorithm(flag_bytes, key, decrypt: bool = False) -> list:
    # Split the encrypted flag by groups of 2 bytes each.
    # We'll decrypt them by chunks.
    new_bytes = []
    it = iter(flag_bytes)
    i = 0
    for L, R in zip(it, it):
        if decrypt:
            new_r, new_l = feistel(R, L, key[i])
        else:
            new_l, new_r = feistel(L, R, key[i])
        new_bytes.append(new_l)
        new_bytes.append(new_r)
        i+=1

    return new_bytes


# Key should be int[4].
def feistel(left: int, right: int, key: list) -> Tuple[int, int]:
    for i in range(16):
        subkey = get_subkey(i, key)
        left, right = do_round(left, right, subkey)
    return (left, right)


def do_round(left: int, right: int, subkey: int) -> Tuple[int, int]:
    return (right, left ^ f(right, subkey))


def f(b: int, k: int) -> int:
    # Check the least significant bit in the key, if it's not set then rotate 'b' to the left.
    # If it's set then rotate to the right.
    for _ in range(8):
        if (k & 1) == 0:
            bit0_b = b & 1
            b = (b >> 1) | (bit0_b << 7)
        else:
            bit7_b = (b >> 7) & 1
            b = (b << 1) & 0xFF
            b |= bit7_b
        k >>= 1
    return b


# Key should be int[4].
# This is simple, returns the key defined by the last 2 bits in index i.
def get_subkey(i: int, key: list) -> int:
    return key[i % 4]


# Returns a int[20] key, each item is a list of int[4].
# So palette 0 keys are indexed as ret[0], palette 1 as ret[1] and so on.
def generate_key(key_in_vram1_bytes: list) -> list:
    ret = []
    it = iter(key_in_vram1_bytes)
    for k_0, k_1 in zip(it, it):
        # The bytes in VRAM1 indicate which palette to retrieve, so let's pick it.
        palette_0 = bytes(int(b, 16) for b in palette_data_dict[k_0][2:6])
        palette_1 = bytes(int(b, 16) for b in palette_data_dict[k_1][2:6])
        palette = [a ^ b for a,b in zip(palette_0, palette_1)]
        # Now we have the 8 colors that form the palette. The first and last colors are used for display,
        # and are not part of the key. So we drop them from our calculation.
        # The only bytes that matter are the two colors in the middle.
        ret.append(palette)
    return ret


if __name__ == "__main__":
    main()
