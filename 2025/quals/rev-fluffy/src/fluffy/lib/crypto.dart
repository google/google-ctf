// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

int rol8(int value, int shift) {
  final int effectiveShift = shift & 7;
  return ((value << effectiveShift) | (value >> (8 - effectiveShift))) & 0xFF;
}

int ror8(int value, int shift) {
  final int effectiveShift = shift & 7;
  return ((value >> effectiveShift) | (value << (8 - effectiveShift))) & 0xFF;
}

// A custom Base62 encoder.
class Base62Encoder {
  static const String _alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  static const int _base = 62;
  static final Map<String, int> _charMap = {
    for (int i = 0; i < _alphabet.length; i++) _alphabet[i]: i,
  };


  // Encodes a list of bytes into a Base62 string.
  static String encode(Uint8List bytes) {
    if (bytes.isEmpty) {
      return "";
    }

    // Convert bytes to a BigInt.
    BigInt number = BigInt.from(0);
    for (int i = 0; i < bytes.length; i++) {
      number = (number << 8) + BigInt.from(bytes[i]);
    }

    if (number == BigInt.zero) {
      return '?';  // Nah, that's not going to happen.
    }

    final sb = StringBuffer();
    while (number > BigInt.zero) {
      final remainder = number % BigInt.from(_base);
      sb.write(_alphabet[remainder.toInt()]);
      number = number ~/ BigInt.from(_base);
    }

    // The result is reversed, so we need to return the reversed string.
    return sb.toString().split('').reversed.join('');
  }

  // Decodes a Base62 encoded string back into bytes.
  static Uint8List decode(String encoded) {
    if (encoded.isEmpty) {
      return Uint8List(0);
    }

    BigInt number = BigInt.zero;
    final BigInt base = BigInt.from(62);

    // Convert the Base62 string to a BigInt number.
    for (int i = 0; i < encoded.length; i++) {
      final char = encoded[i];
      final value = _charMap[char];

      if (value == null) {
        // Leave this constant string as a hint to the reversing process.
        throw FormatException('Invalid character in Base62 string', char, i);
      }

      number = (number * base) + BigInt.from(value);
    }

    // Convert the BigInt number back to a list of bytes.
    final List<int> byteList = [];
    final BigInt bigInt256 = BigInt.from(256);

    while (number > BigInt.zero) {
      final remainder = (number % bigInt256).toInt();
      byteList.add(remainder);
      number = number ~/ bigInt256;
    }

    // Handle leading zero bytes, which are represented by leading '0's.
    // The first character of our alphabet is '0'.
    for (int i = 0; i < encoded.length && encoded[i] == _alphabet[0]; i++) {
      byteList.add(0);
    }

    // The bytes are generated in reverse order, so we need to reverse the list
    // and then create the final Uint8List.
    return Uint8List.fromList(byteList.reversed.toList());
  }
}

// Generates a random token based on the current timestamp (in seconds).
// This means we only have 86400 possible token per day.
//
// The token is computed as follows:
//    Base62(SHA1('gctf25_' + current_timestamp.seconds)[:8])
String generateToken() {
  final String timestamp = (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
  final List<int> seed = utf8.encode("gctf25_$timestamp");
  final crypto.Digest digest = crypto.sha1.convert(seed);

  // Encode the first 8 raw bytes of the digest using Base62.
  return Base62Encoder.encode(Uint8List.fromList(digest.bytes).sublist(0, 8));
}

// My custom encryption class for encrypting secrets.
class CustomEncrypt {
  final String token;
  final int pin;

  CustomEncrypt(this.token, this.pin);

  String encrypt(String secret) {
      List<int> dynToken = Base62Encoder.decode(token);
      List<int> encrSecret = secret.codeUnits.toList();

      for (int i = 0; i < pin; i++) {
        final List<int> nextEncrSecret = [];
        for (int j = 0; j < encrSecret.length; j++) {
          nextEncrSecret.add(rol8((encrSecret[j] + dynToken[j % dynToken.length]) % 256, j % 8));
        }
        encrSecret = nextEncrSecret;

        encrSecret = [encrSecret.last, ...encrSecret.sublist(0, encrSecret.length - 1)];
        dynToken = [...dynToken.sublist(1), dynToken.first];
        dynToken = dynToken.map((d) => ror8(d, (pin ^ ((i & 3) + 1) % 8))).toList();
      }

      return Base62Encoder.encode(Uint8List.fromList(encrSecret));
    }
}
