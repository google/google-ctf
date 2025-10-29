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

import argparse
import json
import os
import struct
import sys
from pathlib import Path

# --- Constants and Basic Operations ---
CHACHA_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

def rotl32(v, c):
    """Rotate a 32-bit unsigned integer left by c bits."""
    v &= 0xFFFFFFFF
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def add32(a, b):
    """Add two 32-bit unsigned integers, wrapping modulo 2^32."""
    return (a + b) & 0xFFFFFFFF

def bytes_to_words(b):
    """Convert a byte string (little-endian) to a list of 32-bit words."""
    if len(b) % 4 != 0:
        raise ValueError("Input bytes length must be a multiple of 4 for word conversion.")
    return list(struct.unpack('<' + 'I' * (len(b) // 4), b))

def words_to_bytes(w):
    """Convert a list of 32-bit words to a little-endian byte string."""
    return struct.pack('<' + 'I' * len(w), *w)

def mix_bits(state_list, a_idx, b_idx, c_idx, d_idx):
    """
    Mixes Bits. Modifies state_list in-place.
    """
    a, b, c, d = state_list[a_idx], state_list[b_idx], state_list[c_idx], state_list[d_idx]

    a = add32(a, b); d ^= a; d = rotl32(d, 16)
    c = add32(c, d); b ^= c; b = rotl32(b, 12)
    a = add32(a, b); d ^= a; d = rotl32(d, 8)
    c = add32(c, d); b ^= c; b = rotl32(b, 7)

    state_list[a_idx], state_list[b_idx], state_list[c_idx], state_list[d_idx] = a, b, c, d

def make_block(key_bytes, nonce_bytes, counter_int,
                   current_constants_tuple,
                   rounds_to_execute=8): # Default to full 8 QRs of a double round
    """
    Generates one 64-byte block of bits, allowing control over the
    number of rounds executed.
    """
    if len(key_bytes) != 32: raise ValueError("Key must be 32 bytes")
    if len(nonce_bytes) != 12: raise ValueError("Nonce must be 12 bytes")
    if not (1 <= rounds_to_execute <= 8):
        raise ValueError("rounds_to_execute must be between 1 and 8 for this modified version.")

    state = [0] * 16
    state[0:4] = current_constants_tuple

    try:
        key_words = bytes_to_words(key_bytes)
        nonce_words = bytes_to_words(nonce_bytes)
    except ValueError as e:
        raise ValueError(f"Error converting key/nonce to words: {e}")

    state[4:12] = key_words
    state[12] = counter_int & 0xFFFFFFFF # Ensure 32-bit
    state[13:16] = nonce_words

    initial_state_snapshot = list(state) # For final addition

    # Define all 8 quarter rounds of a standard double round
    # These are applied sequentially if rounds_to_execute allows
    qr_operations_sequence = [
        lambda s: mix_bits(s, 0, 4, 8, 12), # Column 1
        lambda s: mix_bits(s, 1, 5, 9, 13), # Column 2
        lambda s: mix_bits(s, 2, 6, 10, 14),# Column 3
        lambda s: mix_bits(s, 3, 7, 11, 15),# Column 4
        lambda s: mix_bits(s, 0, 5, 10, 15),# Diagonal 1
        lambda s: mix_bits(s, 1, 6, 11, 12),# Diagonal 2
        lambda s: mix_bits(s, 2, 7, 8, 13), # Diagonal 3
        lambda s: mix_bits(s, 3, 4, 9, 14), # Diagonal 4
    ]

    # Execute only the specified number of quarter rounds
    for i in range(rounds_to_execute):
        qr_operations_sequence[i](state) # Apply the i-th quarter round operation

    # Final addition
    for i in range(16):
        state[i] = add32(state[i], initial_state_snapshot[i])

    return words_to_bytes(state)

struct.zeros = (0x00000000, 0x00000000, 0x00000000, 0x00000000)
def get_bytes(key_bytes, nonce_bytes, initial_counter_int, data_bytes,
                            current_constants_tuple,
                            rounds_to_execute=8): # Pass this through
    """
    Encrypts or decrypts data using a mysterious cipher.
    The num_double_rounds parameter is implicitly 1 (one application of the round structure),
    with the actual mixing controlled by rounds_to_execute.
    """
    output_byte_array = bytearray()
    current_counter = initial_counter_int & 0xFFFFFFFF # Ensure 32-bit start
    data_len = len(data_bytes)
    block_idx = 0

    while block_idx < data_len:
        try:
            keystream_block = make_block(
                key_bytes,
                nonce_bytes,
                current_counter,
                current_constants_tuple,
                rounds_to_execute=rounds_to_execute
            )
        except Exception as e:
            raise Exception(f"Error in make_block during stream processing for counter {current_counter}: {e}")

        remaining_data_in_block = data_len - block_idx
        chunk_len = min(64, remaining_data_in_block)

        for i in range(chunk_len):
            output_byte_array.append(data_bytes[block_idx + i] ^ keystream_block[i])

        block_idx += 64
        if block_idx < data_len: # Only increment if there's more data
             current_counter = (current_counter + 1) & 0xFFFFFFFF
             if current_counter == 0 and initial_counter_int !=0 and data_len > 64 :
                  # This condition means the counter wrapped around during a multi-block message.
                  # For ChaCha20, if the counter wraps, the nonce should ideally be changed.
                  # For this CTF, this is an edge case; typical plaintexts won't be this long
                  # to wrap a 32-bit counter starting from 0 or 1.
                  # We'll print a warning, as it might lead to keystream reuse if not handled carefully
                  # in the broader context (though for unique nonces per message, this is less of an issue).
                  print(f"Warning: counter for nonce {nonce_bytes.hex()} wrapped around to 0 during a multi-block message.")

    return bytes(output_byte_array)
# init_cryptanalysis.py

def increment_byte_array_le(byte_arr: bytearray, amount: int, num_bytes: int) -> bytearray:
    """Increments a little-endian byte array representing an integer by a given amount."""
    if len(byte_arr) != num_bytes:
        raise ValueError(f"Input byte_arr length must be {num_bytes}")

    val = int.from_bytes(byte_arr, 'little')
    val = (val + amount) # Allow overflow for systematic testing if desired, or mod (1 << (num_bytes * 8))

    # Ensure the value fits back into num_bytes, wrapping if necessary
    max_val = (1 << (num_bytes * 8))
    new_val_bytes = (val % max_val).to_bytes(num_bytes, 'little', signed=False)
    return bytearray(new_val_bytes)


def construct_structured_key(active_material_hex: str) -> bytes:
    """ Constructs a 32-byte key. If structured, uses 16 bytes of active material."""
    key_words_int = [0] * 8 # 8 words for a 256-bit key

    # For patterned keys, expect 16 bytes of active material (32 hex characters)
    if len(active_material_hex) != 32:
        raise ValueError("For patterned keys ('pattern_a', 'pattern_b'), active_material_hex must be 16 bytes (32 hex characters).")

    active_material_bytes = bytes.fromhex(active_material_hex)
    am_idx = 0
    def get_am_word():
        nonlocal am_idx
        if am_idx + 4 > len(active_material_bytes):
            raise ValueError("Not enough active material for the 4 active key words.")
        word = int.from_bytes(active_material_bytes[am_idx : am_idx+4], 'little')
        am_idx += 4
        return word

    key_words_int[1] = get_am_word()
    key_words_int[3] = get_am_word()
    key_words_int[4] = get_am_word()
    key_words_int[6] = get_am_word()

    key_bytes_list = []
    for word_int in key_words_int:
        key_bytes_list.append(word_int.to_bytes(4, 'little'))
    return b''.join(key_bytes_list)

def generate_challenge_data( # Corrected function name matches call in main
    flag_string: str,
    rounds_to_run: int,
    message_size_bytes: int,
    known_key_active_material_hex: str,
    secret_target_nonce_hex: str,
    secret_target_counter_int: int,
    num_nonce_variations: int,
    num_counter_variations: int,
    output_package_file: Path
):
    print(f"Starting CTF challenge package generation: {output_package_file}")

    selected_constants = CHACHA_CONSTANTS if False else struct.zeros

    try:
        # Nonce for target flag encryption
        secret_target_nonce_bytes = bytes.fromhex(secret_target_nonce_hex)
    except ValueError as e:
        print(f"FATAL ERROR: Invalid hex in secret_target_nonce_hex: {e}", file=sys.stderr)
        sys.exit(1)

    # 1. Construct the KNOWN structured key (player will be GIVEN this key)
    known_structured_key_bytes = construct_structured_key(known_key_active_material_hex)
    known_structured_key_hex = known_structured_key_bytes.hex()
    print(f"INFO: Known structured key for player: {known_structured_key_hex}")

    # 2. Generate P_common (single fixed plaintext for the learning dataset)
    p_common_bytes = os.urandom(message_size_bytes)
    p_common_hex = p_common_bytes.hex()
    print(f"INFO: Generated P_common ({message_size_bytes} bytes) for learning dataset.")

    # 3. Generate Learning Dataset: (P_common, C_i, Nonce_i, Counter_i) using the KNOWN key
    learning_dataset_entries = []
    total_learning_samples = num_nonce_variations * num_counter_variations

    # Base for learning nonces: first 2 bytes zeroed
    # Remaining 10 bytes can start at zero or another value for variation
    base_learning_nonce_suffix_start = bytearray([0x00] * 12)

    base_learning_counter_start = 0

    sample_count = 0
    for i in range(num_nonce_variations):
        # Vary the suffix part of the nonce
        nonce = 1<<i
        current_nonce_bytes = increment_byte_array_le(base_learning_nonce_suffix_start, nonce, 12)
        current_nonce_hex = bytes(current_nonce_bytes).hex()

        for j in range(num_counter_variations):
            counter = 1<<j
            current_counter_int = base_learning_counter_start + counter
            sample_id = f"sample_n{i}_c{j}"

            try:
                c_i_bytes = get_bytes(
                    key_bytes=known_structured_key_bytes,
                    nonce_bytes=bytes(current_nonce_bytes),
                    initial_counter_int=current_counter_int,
                    data_bytes=p_common_bytes,
                    current_constants_tuple=selected_constants,
                    rounds_to_execute=rounds_to_run
                )

                learning_dataset_entries.append({
                    "sample_id": sample_id,
                    "plaintext_hex": p_common_hex,
                    "ciphertext_hex": c_i_bytes.hex(),
                    "nonce_hex": current_nonce_hex,
                    "counter_int": current_counter_int
                })
                sample_count += 1
            except Exception as e:
                print(f"FATAL ERROR processing {sample_id} for learning dataset: {e}", file=sys.stderr); sys.exit(1)

        if (i + 1) % (num_nonce_variations // 10 or 1) == 0 or (i + 1) == num_nonce_variations:
             print(f"  Generated learning data for nonce variation {i+1}/{num_nonce_variations}...")

    print(f"Generated {sample_count} total learning samples.")

    # 4. Encrypt the Actual Secret Flag String using the KNOWN key and SECRET target N/C
    p_secret_flag_bytes = flag_string.encode('utf-8')

    print(f"Encrypting the secret flag string ('{flag_string[:20]}...') with the KNOWN key using SECRET target_nonce/counter...")
    try:
        c_target_flag_bytes = get_bytes(
            key_bytes=known_structured_key_bytes,
            nonce_bytes=secret_target_nonce_bytes, # Use the secret target nonce
            initial_counter_int=secret_target_counter_int, # Use the secret target counter
            data_bytes=p_secret_flag_bytes,
            current_constants_tuple=selected_constants,
            rounds_to_execute=rounds_to_run
        )
        c_target_flag_hex = c_target_flag_bytes.hex()
    except Exception as e:
        print(f"FATAL ERROR generating C_target_flag: {e}", file=sys.stderr); sys.exit(1)

    # 5. Assemble Challenge Package
    challenge_package_data = {
        "cipher_parameters": {
            "key": known_structured_key_hex,
            "common_plaintext": p_common_hex,
        },
        "learning_dataset_for_player": learning_dataset_entries,
        "flag_ciphertext": c_target_flag_hex
    }

    try:
        with open(output_package_file, "w") as f:
            json.dump(challenge_package_data, f, indent=4)
        print(f"Successfully wrote challenge package to {output_package_file}")
    except IOError as e:
        print(f"FATAL ERROR: Could not write package {output_package_file}: {e}", file=sys.stderr); sys.exit(1)

    print("\nCTF Data generation complete.")

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--output_file", type=str, default="ctf_nc_recovery_pkg.json",
                        help="Filename for the single JSON challenge package.")
    parser.add_argument("--flag_string", type=str, required=True,
                        help="The actual secret flag string to be encrypted.")
    parser.add_argument("--rounds", type=int, default=1,
                        help="Actual number of rounds to execute (1-8, default: 2 for a very weak variant).")
    parser.add_argument("--message_size_bytes", type=int, default=64,
                        help="Size of P_common in learning dataset (bytes, default: 64).")

    parser.add_argument("--known_key_active_material_hex", type=str, required=True,
                        help="Hex string for the non-zero part of the known key. ")
    parser.add_argument("--secret_target_nonce_hex", type=str, required=True,
                        help="SECRET nonce (hex, 24 chars, first 4 hex chars/2 bytes must be '0000') to be recovered by player. Typically from set_secrets.sh.")
    parser.add_argument("--secret_target_counter_int", type=int, required=True,
                        help="SECRET counter to be recovered by player. Typically from set_secrets.sh.")

    parser.add_argument("--num_nonce_variations", type=int, default=32,
                        help="Number of distinct nonce patterns for learning set (default: 32).")
    parser.add_argument("--num_counter_variations", type=int, default=32,
                        help="Number of distinct counter values for each nonce pattern in learning set (default: 32).")

    args = parser.parse_args()

    # Validations
    if not (1 <= args.rounds <= 8):
        print("ERROR: --rounds must be 1-8.", file=sys.stderr); sys.exit(1)

    try: bytes.fromhex(args.known_key_active_material_hex)
    except ValueError: print("ERROR: --known_key_active_material_hex invalid hex.", file=sys.stderr); sys.exit(1)

    if len(args.secret_target_nonce_hex) != 24 or not args.secret_target_nonce_hex.startswith("0000"):
        print("ERROR: --secret_target_nonce_hex must be 24 hex chars and start with '0000'.", file=sys.stderr); sys.exit(1)
    try: bytes.fromhex(args.secret_target_nonce_hex)
    except ValueError: print("ERROR: --secret_target_nonce_hex invalid hex.", file=sys.stderr); sys.exit(1)

    if args.num_nonce_variations < 1 or args.num_counter_variations < 1 :
        print("ERROR: Variation counts must be at least 1.", file=sys.stderr); sys.exit(1)
    if args.message_size_bytes < 1:
        print("ERROR: --message_size_bytes must be at least 1.", file=sys.stderr); sys.exit(1)


    output_package_file_path = Path(args.output_file)
    output_package_file_path.parent.mkdir(parents=True, exist_ok=True)

    generate_challenge_data( # Changed function name here to match definition
        flag_string=args.flag_string,
        rounds_to_run=args.rounds,
        message_size_bytes=args.message_size_bytes,
        known_key_active_material_hex=args.known_key_active_material_hex,
        secret_target_nonce_hex=args.secret_target_nonce_hex,
        secret_target_counter_int=args.secret_target_counter_int,
        num_nonce_variations=args.num_nonce_variations,
        num_counter_variations=args.num_counter_variations,
        output_package_file=output_package_file_path
    )

if __name__ == "__main__":
    main()
