#!/usr/bin/env python3
# Copyright (c) 2015-2020 Damien Ciabrini
# This file is part of ngdevkit
#
# ngdevkit is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# ngdevkit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ngdevkit.  If not, see <http://www.gnu.org/licenses/>.

"""tiletool.py - Neo Geo graphics ROM management

Creates ROMs from 2D images or extract contents of existing ROMs.

This tool can generate 'fix' or 'sprite' ROMs, and relies on
PyGame to convert ROMs to/from common image formats such as BMP or GIF.
"""

import struct
import os
import sys
import argparse
from random import randint

os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = '1'
os.environ['SDL_VIDEODRIVER'] = 'dummy'
os.environ['SDL_AUDIODRIVER'] = 'dummy'
import pygame


class converter(object):
    """Base converter functions: extraction, creation"""
    def __init__(self, args):
        self.args = args
        self.multiple = 0
        self.edge = 0

    def open_rom(self, mode):
        """Init ROM I/O access"""
        pass

    def close_rom(self, mode):
        """Close opened ROM"""
        pass

    def read_tile_from_rom(self):
        """Load the next tile from the ROM file"""
        pass

    def write_tile_to_rom(self, t):
        """Write one tile into the ROM file"""
        pass

    def pos2D_iterator(self, width):
        """Simple generator for iterating tiles in an image"""
        y = 0
        while True:
            for x in range(0, width, self.edge):
                yield (x, y)
            y += self.edge

    def validate_extract(self):
        """Common input checks for extract command"""
        if self.args.output:
            if len(self.args.output) != 1:
                sys.exit("error: expected one image file, given: %s" %
                         " ".join(self.args.output))
            self.out = self.args.output[0]
        else:
            self.out = os.path.splitext(self.in1)[0]+'.bmp'

        if self.size % self.multiple != 0:
            sys.exit("error: ROM size must be a multiple of %d" %
                     self.multiple)

    def extract(self):
        """Extract contents of ROM to a 2D image"""
        self.open_rom('rb')
        num_tiles = os.path.getsize(self.in1)//self.multiple
        tiles_per_line = 20 if not self.args.width \
            else self.args.width//self.edge
        lines = (num_tiles+(tiles_per_line-1))//tiles_per_line
        dest_width = tiles_per_line*self.edge if not self.args.width \
            else self.args.width
        dest_height = lines*self.edge

        if self.args.verbose:
            print("input has %d tiles" % (num_tiles))
            print("destination will hold %d tiles (%dpx x %dpx)" % \
                (tiles_per_line*lines, dest_width, dest_height))

        d = pygame.Surface((dest_width, dest_height), depth=8)
        d.set_palette([(0, 0, 0)] +
                      [(randint(100, 255),
                        randint(100, 255),
                        randint(100, 255)) for i in range(1, 16)])
        dpa = pygame.PixelArray(d)

        edge = self.edge
        i = self.pos2D_iterator(dest_width)
        for n in range(num_tiles):
            (x, y) = next(i)
            t = self.read_tile_from_rom()
            tpa = pygame.PixelArray(t)
            dpa[x:x+edge, y:y+edge] = tpa

        pygame.image.save(d, self.out)
        self.close_rom()

    def validate_create(self):
        """Common input checks for create command"""
        self.in1 = self.args.FILE[0]
        self.img = pygame.image.load(self.in1)

        if self.img.get_width() % self.edge != 0:
            sys.exit("error: image width is not a multiple of %d" % self.edge)
        if self.img.get_height() % self.edge != 0:
            sys.exit("error: image height is not a multiple of %d" % self.edge)

        self.size = self.args.size
        if self.size and self.size % self.multiple != 0:
            sys.exit("error: ROM size must be a multiple of %d" %
                     self.multiple)

    def create(self):
        """Create a graphics ROM from the contents of a 2D image"""
        self.open_rom('wb')
        edge = self.edge
        num_tiles = int((self.img.get_width() / edge) * (self.img.get_height() / edge))
        # limit the processing of tiles up to size bytes
        if self.size:
            if self.size//self.multiple<num_tiles:
                num_tiles = self.size//self.multiple
        dpa = pygame.PixelArray(self.img)
        i = self.pos2D_iterator(self.img.get_width())

        for n in range(num_tiles):
            (x, y) = next(i)
            t = pygame.Surface((edge, edge), depth=8)
            tpa = pygame.PixelArray(t)
            tpa[0:edge, 0:edge] = dpa[x:x+edge, y:y+edge]
            self.write_tile_to_rom(t)

        self.close_rom()


class fix_converter(converter):
    """Specialization for fix tile ROM format"""

    def __init__(self, args):
        self.args = args
        self.multiple = 32
        self.edge = 8

    def open_rom(self, mode):
        """I/O for ROM file xxx.s1"""
        self.fd1 = open(self.in1 if mode == 'rb' else self.out1, mode)

    def close_rom(self):
        if self.size:
            padding=self.size-self.fd1.tell();
            if padding>0:
                self.fd1.write(bytes.fromhex("00"*padding))
        self.fd1.close()

    def validate_extract(self):
        """Fix tile checks for extract command"""
        if len(self.args.FILE) != 1:
            sys.exit("error: expected one ROM file, given: %s" %
                     " ".join(self.args.FILE))
        self.in1 = self.args.FILE[0]

        self.size = self.args.size
        if not self.size:
            sizein1 = os.path.getsize(self.in1)
            self.size = sizein1

        super(fix_converter, self).validate_extract()

    def validate_create(self):
        """Fix tile checks for create command"""
        if not self.args.output:
            self.args.output = ['none']
        if len(self.args.output) != 1:
            sys.exit("error: expected one ROM file, given: %s" %
                     " ".join(self.args.output))
        self.out1 = self.args.output[0]

        super(fix_converter, self).validate_create()

    def read_tile_from_rom(self):
        """Fix tile loader"""
        surf_buf = bytearray(64)
        for xa, xb in ((4, 5), (6, 7), (0, 1), (2, 3)):
            for y in range(8):
                twopix = ord(self.fd1.read(1))
                pixa = twopix & 0xf
                pixb = (twopix >> 0x4) & 0xf
                surf_buf[(8*y)+xa] = pixa
                surf_buf[(8*y)+xb] = pixb

        t = pygame.image.fromstring(bytes(surf_buf), (8, 8), "P")
        return t

    def write_tile_to_rom(self, t):
        """Fix tile writer"""
        surf_buf = t.get_buffer().raw
        for xa, xb in ((4, 5), (6, 7), (0, 1), (2, 3)):
            for y in range(8):
                pixa = surf_buf[(8*y)+xa]
                pixb = surf_buf[(8*y)+xb] << 4
                self.fd1.write(struct.pack('B', pixb | pixa))


class sprite_converter(converter):
    """Specialization for sprite tile ROM format

    A 16x16 sprite tile takes 16 * 16 * 4bits = 1024bits = 128bytes.
    It's split into 4 8x8 blocks, stored as sequences of horizontal rows.
    Each row is encoded in 4 successive bitplanes of 8 bits
    over roms c1 (plane 1; plane 2) and c2 (plane 3; plane 4).
    """

    def __init__(self, args):
        self.args = args
        self.multiple = 64
        self.edge = 16

    def open_rom(self, mode):
        """I/O for pair of ROM files xxx-c1.c1 and xxx-c2.c2"""
        self.fd1 = open(self.in1 if mode == 'rb' else self.out1, mode)
        self.fd2 = open(self.in2 if mode == 'rb' else self.out2, mode)

    def close_rom(self):
        if self.size:
            padding=self.size-self.fd1.tell();
            if padding>0:
                self.fd1.write(bytes.fromhex("00"*padding))
                self.fd2.write(bytes.fromhex("00"*padding))
        self.fd1.close()
        self.fd2.close()

    def validate_extract(self):
        """Sprite tile checks for extract command"""
        if len(self.args.FILE) != 2:
            sys.exit("error: expected two ROM files, given: %s" %
                     " ".join(self.args.FILE))
        self.in1 = self.args.FILE[0]
        self.in2 = self.args.FILE[1]

        self.size = self.args.size
        if not self.size:
            sizein1 = os.path.getsize(self.in1)
            sizein2 = os.path.getsize(self.in2)
            if sizein1 != sizein2:
                sys.exit("error: ROM files must have the same size")
            self.size = sizein1

        super(sprite_converter, self).validate_extract()

    def validate_create(self):
        """Sprite tile checks for create command"""
        if not self.args.output:
            self.args.output = ['none']
        if len(self.args.output) != 2:
            sys.exit("error: expected two ROM files, given: %s" %
                     " ".join(self.args.output))
        self.out1 = self.args.output[0]
        self.out2 = self.args.output[1]

        super(sprite_converter, self).validate_create()

    def read_tile_from_rom(self):
        """Sprite tile loader"""
        surf_buf = bytearray(256)

        for tile8x8_off in (8, 136, 0, 128):
            surf_off = tile8x8_off

            for y in range(8):
                row_bitplane1 = ord(self.fd1.read(1))
                row_bitplane2 = ord(self.fd1.read(1))
                row_bitplane3 = ord(self.fd2.read(1))
                row_bitplane4 = ord(self.fd2.read(1))

                for x in range(8):
                    bp1 = (row_bitplane1 >> x) & 1
                    bp2 = (row_bitplane2 >> x) & 1
                    bp3 = (row_bitplane3 >> x) & 1
                    bp4 = (row_bitplane4 >> x) & 1
                    col = (bp4 << 3) + (bp3 << 2) + (bp2 << 1) + bp1
                    surf_buf[surf_off] = col

                    surf_off += 1
                surf_off += 8
        t = pygame.image.fromstring(bytes(surf_buf), (16, 16), "P")
        return t

    def write_tile_to_rom(self, t):
        """Sprite tile writer"""
        surf_buf = t.get_buffer().raw
        for tile8x8_off in (8, 136, 0, 128):
            surf_off = tile8x8_off

            for y in range(8):
                row_bitplane1 = 0
                row_bitplane2 = 0
                row_bitplane3 = 0
                row_bitplane4 = 0

                for x in range(8):
                    col = surf_buf[surf_off]
                    row_bitplane1 += ((col >> 0) & 1) << x
                    row_bitplane2 += ((col >> 1) & 1) << x
                    row_bitplane3 += ((col >> 2) & 1) << x
                    row_bitplane4 += ((col >> 3) & 1) << x
                    surf_off += 1

                self.fd1.write(struct.pack('2B', row_bitplane1, row_bitplane2))
                self.fd2.write(struct.pack('2B', row_bitplane3, row_bitplane4))
                surf_off += 8


def main():
    pygame.display.init()

    parser = argparse.ArgumentParser(
        description='Neo Geo graphics ROM management.')

    paction = parser.add_argument_group('action')
    pmode = paction.add_mutually_exclusive_group(required=True)
    pmode.add_argument('-x', '-extract', action='store_true',
                       help='extract tiles from ROM into a 2D image')
    pmode.add_argument('-c', '-create', action='store_true',
                       help='create ROM with tiles from a 2D image')

    ptype = parser.add_mutually_exclusive_group()
    ptype.add_argument('--fix', action='store_true',
                       help='8x8 fix tile mode')
    ptype.add_argument('--sprite', action='store_true',
                       help='16x16 sprite tile mode [default]')

    parser.add_argument('FILE', nargs='+', help='file to process')
    parser.add_argument('-o', '--output', nargs='+',
                        help='name of output file')

    parser.add_argument('-s', '--size', metavar='BYTES', type=int,
                        help='size of the generated ROM (create)')
    parser.add_argument('-w', '--width', metavar='PIXELS', type=int,
                        help='width of the generated 2D image (extract)')

    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='print details of processing')

    arguments = parser.parse_args()

    if arguments.fix:
        conv = fix_converter(arguments)
    else:
        conv = sprite_converter(arguments)

    if arguments.x:
        conv.validate_extract()
        conv.extract()

    elif arguments.c:
        conv.validate_create()
        conv.create()


if __name__ == '__main__':
    main()
