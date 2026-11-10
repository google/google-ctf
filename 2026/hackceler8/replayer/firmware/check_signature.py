#!/usr/bin/env python3
"""Offline check: will the RP2350 boot ROM accept this image under a given OTP config?
Usage:
  check_signed.py IMAGE(.elf|.uf2|.bin) OTP.json [--info-file picotool_info.txt]
OTP.json uses the picotool `otp load` format, e.g.
  {"bootkey0": [32 bytes], "bootkey1": [...],
   "boot_flags1": {"key_valid": 3, "key_invalid": 12}}
What is checked:
  1. picotool cryptographically verifies hash + signature of the IMAGE_DEF the ROM
     will pick (the last IMAGE_DEF in the block loop).
  2. That IMAGE_DEF is an ARM Secure image for RP2350.
  3. SHA-256(public key in the signature) equals a BOOTKEYn whose slot is valid
     (KEY_VALID set, KEY_INVALID clear).
  4. For .uf2: every block has the rp2350-arm-s family ID and targets flash.
Requires `picotool` on PATH unless --info-file is given.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
UF2_MAGIC0, UF2_MAGIC1, UF2_MAGIC_END = 0x0A324655, 0x9E5D5157, 0x0AB16F30
UF2_FLAG_FAMILY_ID = 0x00002000
FAMILIES = {
    0xE48BFF56: "rp2040",
    0xE48BFF57: "absolute",
    0xE48BFF58: "data",
    0xE48BFF59: "rp2350-arm-s",
    0xE48BFF5A: "rp2350-riscv",
    0xE48BFF5B: "rp2350-arm-ns",
}
def parse_picotool_info(text):
    """Returns (program_info dict, [block dicts]) from `picotool info -a` output."""
    blocks, program, current = [], {}, None
    for line in text.splitlines():
        if re.match(r"^\S", line):  # section header
            m = re.match(r"^Metadata Block (\d+)", line)
            current = {} if m else None
            if m:
                blocks.append(current)
            elif line.startswith("Program Information"):
                current = program
            continue
        m = re.match(r"^\s+([^:]+?):\s+(.*)$", line)
        if m and current is not None:
            key, val = m.group(1).strip(), m.group(2).strip()
                        # load map entries / repeated keys: keep a list
            if key in current:
                current.setdefault(key + " (all)", [current[key]]).append(val)
            current[key] = val
    return program, blocks

def check_uf2(path):
    errors, families, addrs = [], set(), []
    data = open(path, "rb").read()
    if len(data) % 512:
        errors.append("UF2 size is not a multiple of 512")
    for off in range(0, len(data) - 511, 512):
        m0, m1, flags, addr, size, _, _, fam = struct.unpack_from("<8I", data, off)
        (mend,) = struct.unpack_from("<I", data, off + 508)
        if (m0, m1, mend) != (UF2_MAGIC0, UF2_MAGIC1, UF2_MAGIC_END):
            errors.append(f"bad UF2 magic in block at file offset {off:#x}")
            continue
        if not flags & UF2_FLAG_FAMILY_ID:
            errors.append(f"block at {addr:#010x} has no family ID")
            continue
        families.add(FAMILIES.get(fam, hex(fam)))
        if fam == 0xE48BFF59:
            addrs.append((addr, addr + size))
    if families - {"rp2350-arm-s", "absolute"}:
        errors.append(f"unexpected UF2 families: {sorted(families)}")
    if addrs:
        lo, hi = min(a for a, _ in addrs), max(b for _, b in addrs)
        print(f"  UF2 families: {sorted(families)}; rp2350-arm-s range {lo:#010x}-{hi:#010x}")
        if not (0x10000000 <= lo and hi <= 0x11000000):
            errors.append("rp2350-arm-s blocks do not all target flash (0x10000000-0x11000000)")
    else:
        errors.append("no rp2350-arm-s blocks found")
    return errors
 
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("otp_json")
    ap.add_argument("--info-file", help="saved `picotool info -a` output instead of running picotool")
    args = ap.parse_args()
    if args.info_file:
        info = open(args.info_file).read()
    else:
        info = subprocess.run(["picotool", "info", "-a", args.image],
                              check=True, capture_output=True, text=True).stdout
    _, blocks = parse_picotool_info(info)
    otp = json.load(open(args.otp_json))
    errors = []
    print(f"Image: {args.image}")
    image_defs = [b for b in blocks if b.get("block type") == "image def"]
    if not image_defs:
        sys.exit("FAIL: no IMAGE_DEF block found")
    chosen = image_defs[-1]  # ROM uses the last IMAGE_DEF in the block loop
    print(f"  ROM will use IMAGE_DEF at {chosen.get('address')} "
          f"({len(image_defs)} IMAGE_DEF(s) in loop)")
    if chosen.get("target chip") != "RP2350" or chosen.get("image type") != "ARM Secure":
        errors.append(f"IMAGE_DEF is {chosen.get('target chip')}/{chosen.get('image type')}, "
                      "need RP2350/ARM Secure")
    for field in ("hash", "signature"):
        if chosen.get(field) != "verified":
            errors.append(f"{field}: {chosen.get(field, 'missing')}")
    pub = chosen.get("public key")
    if not pub:
        errors.append("no public key in chosen IMAGE_DEF (image is not signed)")
    else:
        key_hash = hashlib.sha256(bytes.fromhex(pub)).digest()
        print(f"  SHA-256(public key) = {key_hash.hex()}")
        flags = otp.get("boot_flags1", {})
        valid, invalid = flags.get("key_valid", 0), flags.get("key_invalid", 0)
        match = None
        for slot in range(4):
            otp_key = otp.get(f"bootkey{slot}")
            if otp_key is None:
                continue
            otp_key = bytes(otp_key)
            if otp_key == key_hash:
                match = slot
            elif otp_key == key_hash[::-1]:
                errors.append(f"bootkey{slot} matches only byte-reversed - check JSON byte order")
        if match is None:
            errors.append("public key hash does not match any BOOTKEY in the OTP config")
        else:
            ok = bool(valid >> match & 1) and not (invalid >> match & 1)
            print(f"  matches bootkey{match}: key_valid={bool(valid >> match & 1)}, "
                  f"key_invalid={bool(invalid >> match & 1)}")
            if not ok:
                errors.append(f"bootkey{match} slot is not valid in this OTP config")
    if args.image.lower().endswith(".uf2"):
        errors += check_uf2(args.image)
    if errors:
        print("FAIL:\n  - " + "\n  - ".join(errors))
        sys.exit(1)
    print("PASS: the ROM should accept this image with this OTP config")

if __name__ == "__main__":
    main()