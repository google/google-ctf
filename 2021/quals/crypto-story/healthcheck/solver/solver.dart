#!/usr/bin/env dart

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
 ***/

import 'dart:convert';
import 'dart:io';
import 'package:ctf_story/private.dart' show crcs, getBits;
import 'package:crclib/crclib.dart';

CrcValue getTarget(String text) {
  final re = RegExp('([0-9a-f]{4}), ([0-9a-f]{8}), ([0-9a-f]{16})');
  final match = re.allMatches(text).last;
  final vals =
      List.generate(3, (i) => BigInt.parse(match.group(i + 1), radix: 16));
  final bigInt = vals[0] << (64 + 32) | vals[1] << 64 | vals[2];
  return CrcValue(bigInt);
}

class Conversation {
  final Socket socket;
  static const String buffaloStory =
      'Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo '
      'Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo '
      'Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo '
      'Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo '
      'Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo '
      'Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo Buffalo.';

  Conversation(this.socket);

  void onData(List<int> data) async {
    final text = utf8.decode(data);
    print(text);
    if (text.startsWith('Hello!')) {
      socket.write(buffaloStory + '\n');
    } else if (text.contains('But I am')) {
      final flipper = CrcFlipper(MultiCrc(crcs));
      final input = buffaloStory.codeUnits;
      final positions = getBits(input);
      final target = getTarget(text);
      final solution = flipper.flipWithData(input, positions, target);
      if (solution != null) {
        final output = List.of(input);
        solution.forEach((p) {
          output[p ~/ 8] ^= 1 << (p % 8);
        });
        socket.write(String.fromCharCodes(output) + '\n');
      } else {
        print('No solution. Try again.');
        socket.destroy();
      }
    }
  }
}

main(List<String> arguments) async {
  final host = arguments[0];
  final port = int.parse(arguments[1]);
  final socket = await Socket.connect(host, port);
  final conversation = Conversation(socket);
  socket.listen(conversation.onData).onDone(() {
    socket.close();
  });
}

