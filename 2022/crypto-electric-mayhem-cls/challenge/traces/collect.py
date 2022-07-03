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


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--plaintext',
      default='output/randdata.txt',
      type=str,
      help='Data passed to firmware')
  parser.add_argument(
      '--ciphertext',
      default='output/printdata.txt',
      type=str,
      help='Data returned from firmware')
  parser.add_argument(
      '--tracedir',
      default='output/traces/trace%05d.trc',
      type=str,
      help='Traces directory')
  parser.add_argument('--ntraces', default=1, type=int, help='Number of traces')
  parser.add_argument(
      'output', metavar='OUTPUT', type=str, help='Output json.gz file')
  args = parser.parse_args()

  pt = [int(l.strip(), 16) for l in open(args.plaintext)]
  ct = [int(l.strip(), 16) for l in open(args.ciphertext)]
  assert (len(pt) == len(ct))
  print('Read {0} pt/ct pairs'.format(len(pt)))
  assert (len(pt) % 16 == 0)
  assert (args.ntraces <= (len(pt) / 16))

  print('Collecting {0} traces'.format(args.ntraces))
  data = []
  for i in range(args.ntraces):
    trace_pt = pt[16 * i:16 * (i + 1)]
    trace_ct = ct[16 * i:16 * (i + 1)]
    trace_pm = [float(l.strip()) for l in open(args.tracedir % (1 + i))]
    data.append({'pt': trace_pt, 'ct': trace_ct, 'pm': trace_pm})

  with gzip.open(args.output, 'w') as output:
    output.write(json.dumps(data).encode('utf-8'))


if __name__ == '__main__':
  main()
