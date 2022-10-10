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
import gzip
import json


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--encaps',
      default='encaps.json.gz',
      type=str,
      help='Keys and ciphertext passed to firmware')
  parser.add_argument(
      '--sessionkeys',
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

  with gzip.open(args.encaps, 'r') as f:
    encaps = json.loads(f.read().decode('utf-8'))

  ss = []
  with open(args.sessionkeys) as f:
    for i in range(args.ntraces):
      ss.append([int(f.readline().strip(), 16) for j in range(32)])
  print('Read {0} ss'.format(len(ss)))

  # Sanity check: session keys unwrap the flag.
  for i, k1 in enumerate(ss):
    k2 = encaps['sessions'][i]['flag_xor_ss']
    unwrap = ''.join([chr(a ^ b) for a, b in zip(k1, k2)])
    assert (unwrap.startswith('CTF{'))
    assert (unwrap.endswith('}'))

  print('Collecting {0} traces'.format(args.ntraces))
  data = {}
  data['pk'] = encaps['pk']
  data['sessions'] = []
  for i in range(args.ntraces):
    trace_flag_xor_ss = encaps['sessions'][i]['flag_xor_ss']
    trace_ct = encaps['sessions'][i]['ct']
    trace_pm = [float(l.strip()) for l in open(args.tracedir % (1 + i))]
    data['sessions'].append({
        'ct': trace_ct,
        'flag_xor_ss': trace_flag_xor_ss,
        'pm': trace_pm
    })

  with gzip.open(args.output, 'w') as output:
    output.write(json.dumps(data).encode('utf-8'))


if __name__ == '__main__':
  main()
