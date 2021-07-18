// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/****
 *
 * DO NOT SHARE!!!
 *
 ****/

import 'dart:math';

import 'package:crclib/catalog.dart';

final crcs = [Crc16(), Crc32C(), Crc64Xz()];

List<String> calculate(List<int> data) => crcs
    .map((c) => c
        .convert(data)
        .toBigInt()
        .toRadixString(16)
        .padLeft(c.lengthInBits ~/ 4, '0'))
    .toList(growable: false);

bool isAlphabet(int c) =>
    (c >= 0x61 && c < 0x61 + 26) || (c >= 0x41 && c < 0x41 + 26);

List<String> randomize(List<int> data) {
  final nrAlphabets = data.where(isAlphabet).length;
  if (nrAlphabets < 256) {
    return null;
  }
  final allowedBits = getBits(data)..shuffle(Random());
  final randomBits = allowedBits.take(128);
  randomBits.forEach((p) {
    data[p ~/ 8] ^= 1 << (p % 8);
  });
  return calculate(data);
}

List<int> getBits(List<int> input) {
  final ret = <int>[];
  for (var i = 0; i < input.length; ++i) {
    if (isAlphabet(input[i])) {
      ret.add(i * 8 + 5);
    }
  }
  return ret;
}
