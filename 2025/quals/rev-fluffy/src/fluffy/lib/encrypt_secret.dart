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

class EncryptSecretPage extends StatefulWidget {
  final Function(SecretEntry newEntry) onSave;

  const EncryptSecretPage({Key? key, required this.onSave}) : super(key: key);

  @override
  _EncryptSecretPageState createState() => _EncryptSecretPageState();
}

class _EncryptSecretPageState extends State<EncryptSecretPage> {
  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _tokenController = TextEditingController();
  final TextEditingController _pinController = TextEditingController();
  final TextEditingController _secretController = TextEditingController();

  @override
  void dispose() {
    _nameController.dispose();
    _tokenController.dispose();
    _pinController.dispose();
    _secretController.dispose();
    super.dispose();
  }

  // Callback for when the save secret button is clicked.
  void _saveSecret() {
    // Make sure that all fields are filled.
    if (_nameController.text.isEmpty ||
        _tokenController.text.isEmpty ||
        _pinController.text.isEmpty ||
        _secretController.text.isEmpty) {
      showWarnSnackBar('Please fill in all fields', context);
      return;
    }

    // Make sure that PIN is exactly 4 digits long.
    if (_pinController.text.length != 4) {
      showWarnSnackBar('PIN must be exactly4  digits', context);
      return;
    }

    // Null PINs cause problems.
    if (int.parse(_pinController.text) == 0) {
      showWarnSnackBar('For security reasons, PIN cannot be 0000', context);
      return;
    }

    // Make sure that both token and secret are ASCII-printable.
    final RegExp printableAscii = RegExp(r'^[\x20-\x7E]+$');
    if (!printableAscii.hasMatch(_tokenController.text)) {
      showWarnSnackBar('Token contains invalid characters', context);
      return;
    }
    if (!printableAscii.hasMatch(_secretController.text)) {
      showWarnSnackBar('Secret contains invalid characters', context);
      return;
    }

    // Get the current timestamp and format it as day only (DD/MM/YYYY).
    final now = DateTime.now();
    final String formattedDate = "${now.day.toString().padLeft(2, '0')}/${now.month.toString().padLeft(2, '0')}/${now.year} ${now.hour.toString().padLeft(2, '0')}:${now.minute.toString().padLeft(2, '0')}";
    final String encryptedSecret;
    try {
      encryptedSecret = CustomEncrypt(
          _tokenController.text,
          int.parse(_pinController.text)).encrypt(_secretController.text);
    } on FormatException {
      showWarnSnackBar('Token contains invalid characters', context);
      return;
    }

    widget.onSave(
        SecretEntry(
            name: _nameController.text,
            token: _nameController.text,
            pin: _pinController.text,
            secret: encryptedSecret,
            date: formattedDate
        )
    );
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'Encrypt New Secret',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _nameController,
              decoration: const InputDecoration(
                labelText: 'Name',
                icon: Icon(Icons.person_outline),
              ),
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _tokenController,
              decoration: const InputDecoration(
                labelText: 'Token',
                icon: Icon(Icons.vpn_key_outlined),
              ),
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _pinController,
              decoration: const InputDecoration(
                labelText: 'PIN',
                icon: Icon(Icons.pin_outlined),
                counterText: "", // Hide the default character counter.
              ),
              keyboardType: TextInputType.number,
              maxLength: 4, // Enforce a max length of 4
              inputFormatters: <TextInputFormatter>[
                FilteringTextInputFormatter.digitsOnly
              ],
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _secretController,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'Secret',
                icon: Icon(Icons.security_outlined),
              ),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: _saveSecret,
              child: const Text('Encrypt & Save Secret'),
            ),
          ],
        ),
      ),
    );
  }
}
