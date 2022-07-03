#!/usr/bin/env python3
#
# Copyright (C) 2022 Google LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
import json
import gzip
from scipy import signal


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--input',
      default='traces_raw.json.gz',
      type=str,
      help='Input traces to downsample')
  parser.add_argument(
      '--factor', default=5, type=int, help='Downsampling factor ')
  parser.add_argument(
      'output', metavar='OUTPUT', type=str, help='Output json.gz file')
  args = parser.parse_args()

  with gzip.open(args.input, 'r') as f:
    data = json.loads(f.read().decode('utf-8'))

  for i in range(len(data)):
    data[i]['pm'] = list(signal.decimate(data[i]['pm'], args.factor))

  with gzip.open(args.output, 'w') as output:
    output.write(json.dumps(data).encode('utf-8'))


if __name__ == '__main__':
  main()
