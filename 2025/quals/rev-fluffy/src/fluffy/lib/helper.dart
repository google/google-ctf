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

// Helper methods shared across files.
import 'package:flutter/material.dart';

// Data model for a secret entry.
class SecretEntry {
  final String name;
  final String token;
  final String pin;
  final String secret; // This contains the encrypted secret.
  final String date;

  SecretEntry({
    required this.name,
    required this.token,
    required this.pin,
    required this.secret,
    required this.date,
  });
}

void showInfoSnackBar(String message, BuildContext context) {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Row(
        children: [
          const Icon(Icons.info, color: Colors.black87),
          const SizedBox(width: 8),
          Expanded(child: Text(message)),
        ],
      ),
      backgroundColor: Colors.lightGreenAccent,
    ),
  );
}

void showWarnSnackBar(String message, BuildContext context) {
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Row(
        children: [
          const Icon(Icons.warning, color: Colors.black87),
          const SizedBox(width: 8),
          Expanded(child: Text(message)),
        ],
      ),
      backgroundColor: Colors.yellow,
    ),
  );
}
