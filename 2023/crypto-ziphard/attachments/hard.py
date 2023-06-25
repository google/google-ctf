#!/usr/bin/python3
# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import struct
import sys
import time

UTF8 = "utf-8-sig"

# PKZIP header information
FLAG_ENCRYPTED = 1
METHOD_STORE = 0

# Local file header
LFH_FMT = "<IHHHHHIIIHH"
LFH_MAGIC = 0x04034b50

# Central directory file header
CD_FMT = "<IHHHHHHIIIHHHHHII"
CD_MAGIC = 0x02014b50

# End of central directory record
ECD_FMT = "<IHHHHIIH"
ECD_MAGIC = 0x06054b50

# CRC, as used by ZIP files
# adapted from CRC code in RFC 1952
crc_table = [0] * 256
def make_crc_table():
    for i in range(256):
        c = i
        for j in range(8):
            if (c & 1) != 0:
                c = 0xedb88320 ^ (c >> 1)
            else:
                c >>= 1
        crc_table[i] = c
make_crc_table()

# update a crc with just one byte, without pre- and post-conditioning
# for use only with the PKWARE cipher
def update_crc1(crc, b):
    return crc_table[(crc ^ b) & 0xff] ^ (crc >> 8)

# update a crc given a buffer of bytes
def update_crc(crc, buf):
    crc ^= 0xffffffff

    for b in buf:
        crc = crc_table[(crc ^ b) & 0xff] ^ (crc >> 8)

    return crc ^ 0xffffffff

# an implementation of the PKWARE cipher as described in APPNOTE.TXT
class PKZIPCipher(object):
    # set key
    def __init__(self, password):
        self.key = [ 305419896, 591751049, 878082192 ]
        for b in password:
            self.update_keys(b)

    # advance the keystream given a plaintext byte
    def update_keys(self, b):
        self.key[0] = update_crc1(self.key[0], b)
        self.key[1] = (self.key[1] + (self.key[0] & 0xff)) & 0xffffffff
        self.key[1] = (self.key[1] * 134775813 + 1) & 0xffffffff
        self.key[2] = update_crc1(self.key[2], self.key[1] >> 24)

    # return the next byte of keystream (without advancing it)
    def decrypt_byte(self):
        temp = (self.key[2] | 2) & 0xffff
        return ((temp * (temp ^ 1)) >> 8) & 0xff

    # decrypt a bytearray of data in-place
    def decrypt_buf(self, buf):
        for i in range(len(buf)):
            c = buf[i] ^ self.decrypt_byte()
            self.update_keys(c)
            buf[i] = c

    # encrypt a bytearray of data in-place
    def encrypt_buf(self, buf):
        for i in range(len(buf)):
            c = buf[i]
            buf[i] ^= self.decrypt_byte()
            self.update_keys(c)

# encrypt the flag, returning nonce+ciphertext ready to go into the ZIP file
def encrypt_flag(flag, password, crc):
    # first, generate the 96-bit nonce
    # for the first 88 bits, use cryptographically secure random bytes
    nonce = bytearray(12)
    nonce[0:11] = os.urandom(11)

    # set the last byte of the nonce to the most significant byte of the
    # CRC, per APPNOTE.TXT. This allows an Unzip program to check whether
    # the supplied password is correct.
    nonce[11] = (crc >> 24) & 0xff

    # initialize the PKWARE cipher using the given password
    cipher = PKZIPCipher(password)

    # first, randomize the state of the cipher by encryption the nonce
    cipher.encrypt_buf(nonce)

    # next, encrypt the plaintext, receiving ciphertext
    flagbuf = bytearray(flag)
    cipher.encrypt_buf(flagbuf)

    # now, prepend the ciphertext with the encrypted nonce and return it
    return nonce + flagbuf

def main():
    # check the arguments
    if len(sys.argv) != 4:
        print("""usage: makezip.py password flag.txt out.zip
     password: password to be used to encrypt flag.txt in the ZIP file
     flag.txt: file containing the flag. The CTF{} wrapper around the flag must be present.
     out.zip: encrypted zip file to be created
""")
        sys.exit(-1)

    # initialize arguments from values
    password = bytes(sys.argv[1], UTF8)
    flag = None
    with open("flag.txt", "r") as flagfile:
        flag = flagfile.read()
    assert flag[:4] == "CTF{"
    assert flag[-1:] == "}"
    assert len(flag) > 5
    flag = bytes(flag, UTF8)
    fout = open(sys.argv[3], "xb")

    # convert time to DOS format
    now = time.localtime()
    ziptime = (now.tm_hour << 11) | (now.tm_min << 5) | now.tm_sec
    zipdate = ((now.tm_year - 1980) << 9) | (now.tm_mon << 5) | now.tm_mday

    # calculate the CRC of the flag, and encrypt it
    flagcrc = update_crc(0, flag)
    eflag = encrypt_flag(flag, password, flagcrc)

    # a ZIP file (with only one encrypted file in it) looks like this:
    # [local file header 1]
    # [filename 1]
    # [Encrypted(nonce || plaintext) 1]
    # [central directory file header 1]
    # [filename 1]
    # [end of central directory record]

    cds = []

    data = os.urandom(4)
    crc = update_crc(0, data)
    edata = encrypt_flag(data, password, crc)
        
    filename = b"junk.dat"
        
    # build the local file header
    lfh = struct.pack(LFH_FMT,
                      LFH_MAGIC,
                      20,
                      FLAG_ENCRYPTED,
                      METHOD_STORE,
                      ziptime,
                      zipdate,
                      crc,
                      len(edata),
                      len(data),
                      len(filename),
                      0)
    
    
    # build the central directory file header
    # buffer the central directories in memory
    cd = struct.pack(CD_FMT,
                     CD_MAGIC,
                     20,
                     20,
                     FLAG_ENCRYPTED,
                     METHOD_STORE,
                     ziptime,
                     zipdate,
                     crc,
                     len(edata),
                     len(data),
                     len(filename),
                     0, 0, 0, 0, 0,
                     fout.tell())
    cds.append(cd + filename)
    
    fout.write(lfh)
    fout.write(filename)
    fout.write(edata)

    # now do the flag
    
    # build the local file header
    lfh = struct.pack(LFH_FMT,
                      LFH_MAGIC,
                      20,
                      FLAG_ENCRYPTED,
                      METHOD_STORE,
                      ziptime,
                      zipdate,
                      flagcrc,
                      len(eflag),
                      len(flag),
                      len(b"flag.txt"),
                      0)
    

    # build the central directory file header
    # buffer the central directories in memory
    cd = struct.pack(CD_FMT,
                     CD_MAGIC,
                     20,
                     20,
                     FLAG_ENCRYPTED,
                     METHOD_STORE,
                     ziptime,
                     zipdate,
                     flagcrc,
                     len(eflag),
                     len(flag),
                     len(b"flag.txt"),
                     0, 0, 0, 0, 0,
                     fout.tell())
    cds.append(cd + b"flag.txt")

    fout.write(lfh)
    fout.write(b"flag.txt")
    fout.write(eflag)

    # write out the central directory
    begin_cd = fout.tell()
    for cd in cds:
        fout.write(cd)
        
    # build the end of central directory record
    ecd = struct.pack(ECD_FMT,
                      ECD_MAGIC,
                      0, 0, len(cds), len(cds),
                      fout.tell() - begin_cd,
                      begin_cd,
                      0)
    fout.write(ecd)

    fout.close()
    sys.exit(0)

main()
