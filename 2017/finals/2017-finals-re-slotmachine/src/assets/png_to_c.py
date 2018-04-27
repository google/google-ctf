#!/usr/bin/python
#
# Copyright 2018 Google LLC
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

import PIL
import PIL.Image

import math
import os
import sys


def compress_array(a, bpp):
    """
    Compresses the data in a using the tags:
    [value/bpp] [n_repeats/(8-bpp))]
    """
    current_val = None
    length = 0
    result = []

    max_len = (1 << (8 - bpp)) - 1
    for v in a:
        assert 0 <= v and v < (1 << bpp)
        if current_val is None:
            current_val = v
        elif current_val != v or length == max_len:
            result.append((current_val << (8 - bpp)) | length)
            current_val = v
            length = 0

        length += 1
    result.append((current_val << (8 - bpp)) | length)

    return result


def ascii_palette(i):
    return [' ', '_', 'X', '*'][i]


def process(fn, fno):
    print("======== Processing {} =======".format(fn))
    img = PIL.Image.open(fn)
    (w, h) = img.size
    data = img.load()

    name = os.path.basename(fn)[:-4]
    assert '-' not in name

    # Minify image
    symbols = set()
    # Crop image
    bx1 = w
    bx2 = 0
    by1 = h
    by2 = 0

    for y in range(h):
        lin = []
        for x in range(w):
            v = data[(x, y)]
            lin += [v]
            symbols.add(v)
            if v:
                if x < bx1:
                    bx1 = x
                if x > bx2:
                    bx2 = x
                if y < by1:
                    by1 = y
                if y > by2:
                    by2 = y

    bpp = math.ceil(math.log2(len(symbols)))

    actual_w = bx2 - bx1 + 1
    actual_h = by2 - by1 + 1
    print("Actual size: {}x{}".format(actual_w, actual_h))

    # Calculate total size
    total_size = math.ceil(actual_w * actual_h / (8 // bpp))
    print("Raw bitmap: {} bytes (using {} bit per pixel)".format(total_size, bpp))

    assert (len(symbols) - 1) == max(symbols), "Palette data not as expected (ordered), can't handle this :<"

    sub_data = []
    ll = []
    # Put cropped image in sub_data, also create ascii dump in `ll`
    for y in range(by1, by2 + 1):
        lin = []
        for x in range(bx1, bx2 + 1):
            sub_data.append(data[(x, y)])
            lin.append(data[(x, y)])
        if bpp <= 2:
            ll.append("// " + "".join([ascii_palette(i) for i in lin]))

    compressed = compress_array(sub_data, bpp)
    print("Compressed: {} bytes".format(len(compress_array(sub_data, bpp))))

    # Ugly code generation code
    c_src = ["constexpr uint8_t {name}_data[{length}] PROGMEM = {{".format(name=name, length=len(compressed))]
    for i in range((len(compressed) + 15) // 16):
        line = []
        for x in range(min(len(compressed) - i * 16, 16)):
            line.append(compressed[i * 16 + x])
        c_src.append("    " + ", ".join(
            ["{}".format(i) for i in line]
        ) + ",")

    c_src.append("};")
    with open(fno, 'w') as f:
        f.write("// Data definition from {}\n".format(fn))
        f.write("\n".join(ll) + "\n")
        f.write("constexpr uint8_t {}_w = {};\n".format(name, actual_w))
        f.write("constexpr uint8_t {}_h = {};\n".format(name, actual_h))
        f.write("constexpr uint8_t {}_bpp = {};\n".format(name, bpp))

        pal = img.getpalette()
        f.write("constexpr uint16_t {}_palette[{}] = {{{}}};\n".format(
            name,
            len(symbols) - 1,
            ", ".join(["RGB888_RGB565(0x{:06X})".format(
                (pal[3 * i] << 16) + (pal[3 * i + 1] << 8) + pal[3 * i + 2]
            ) for i in range(1, len(symbols))])
        ))
        f.write("\n".join(c_src) + "\n")


if __name__ == '__main__':
    assert len(sys.argv) == 3, "C'mon"
    process(*sys.argv[1:])
