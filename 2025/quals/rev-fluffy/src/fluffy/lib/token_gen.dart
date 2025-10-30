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

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'crypto.dart';
import 'helper.dart';

class TokenGeneratorPage extends StatefulWidget {
  const TokenGeneratorPage({Key? key}) : super(key: key);

  @override
  _TokenGeneratorPageState createState() => _TokenGeneratorPageState();
}

class _TokenGeneratorPageState extends State<TokenGeneratorPage> {
  final TextEditingController _genTokenController = TextEditingController();

  @override
  void dispose() {
    _genTokenController.dispose();
    super.dispose();
  }

  // Generates a random token based on the current timestamp.
  void _generateSha1Token() {
    _genTokenController.text = generateToken();
    setState(() {}); // Rebuild to update the UI.
  }

  // Copies the generated string to the clipboard.
  void _copyToClipboard() {
    if (_genTokenController.text.isNotEmpty) {
      Clipboard.setData(ClipboardData(text: _genTokenController.text));
      showInfoSnackBar('Copied to clipboard!', context);
    } else {
      showWarnSnackBar('You must generate a token first', context);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: <Widget>[
          const Text(
            'Use a token to protect your secrets:',
            style: TextStyle(fontSize: 18),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 20),
          TextField(
            controller: _genTokenController,
            readOnly: true,
            textAlign: TextAlign.center,
            style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold, fontFamily: 'monospace'),
            decoration: const InputDecoration(
              hintText: 'Press "Generate"',
            ),
          ),
          const SizedBox(height: 20),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              ElevatedButton.icon(
                icon: const Icon(Icons.casino),
                onPressed: _generateSha1Token,
                label: const Text('Generate'),
              ),
              ElevatedButton.icon(
                icon: const Icon(Icons.copy),
                onPressed: _copyToClipboard,
                label: const Text('Copy'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
