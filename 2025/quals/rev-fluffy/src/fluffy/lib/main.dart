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
import 'decrypt_secret.dart';
import 'encrypt_secret.dart';
import 'home.dart';
import 'crypto.dart';
import 'token_gen.dart';
import 'helper.dart';
import 'view_secrets.dart';


// The main entry point for the Fluffy App.
void main() {
  runApp(const FluffyApp());
}

// FluffyApp is the root widget.
class FluffyApp extends StatelessWidget {
  const FluffyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      // The title of the application, used by the operating system.
      title: 'Fluffy Locking App',
      // Define the dark theme for the application.
      darkTheme: ThemeData(
        brightness: Brightness.dark,
        primarySwatch: Colors.lightGreen,
        scaffoldBackgroundColor: const Color(0xFF121212), // Standard dark background
        cardColor: const Color(0xFF1E1E1E), // Slightly lighter for cards
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(
            borderSide: BorderSide(color: Colors.white38),
          ),
          focusedBorder: OutlineInputBorder(
            borderSide: BorderSide(color: Colors.lightGreen),
          ),
          labelStyle: TextStyle(color: Colors.white70),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: Colors.lightGreenAccent,
            foregroundColor: Colors.black87,
          ),
        ),
      ),
      themeMode: ThemeMode.dark,
      home: const MainPage(),
      debugShowCheckedModeBanner: false,
    );
  }
}

// MainPage is the main screen of the application.
class MainPage extends StatefulWidget {
  const MainPage({super.key});

  @override
  _MainPageState createState() => _MainPageState();
}

// This class holds the state for the MainPage widget.
class _MainPageState extends State<MainPage> {
  // Index to keep track of the selected page. 0: Home, 1: View Secrets, etc.
  int _selectedIndex = 0;

  // The list of the predefined secrets. The flag is encrypted in them.
  final List<SecretEntry> _secrets = [
      // Let's make it easy and give out the exact second on the first secret.
      SecretEntry(date: '04/08/2023 13:37', name: 'Top Secret',   token: '-', pin: '-', secret: 'fmMf7mIMbHcPoQmLGx1CO0XVGBmhjTaYhB0'),
      SecretEntry(date: '07/09/2024 18:52', name: 'Lara Croft',   token: '-', pin: '-', secret: '5O6WRgCajs3QSTyohnu2hldds18mjkx'),
      SecretEntry(date: '03/03/2025 22:07', name: 'Eugene Krabs', token: '-', pin: '-', secret: 'fgv99dOvazsvEESh7DPKbb3k0I3RW')
  ];

  // Updates the UI to show the selected page's content.
  void _selectPage(int index) {
    setState(() {
      _selectedIndex = index;
    });

    Navigator.of(context).pop(); // Close the drawer after selecting an item.
  }

  // Adds a new secret entry as a single item to the secrets list.
  void _addProfileData(SecretEntry newEntry) {
    setState(() {
      _secrets.add(newEntry);
      _selectedIndex = 1; // Go to the secrets page to see the new entry.
    });

    showInfoSnackBar('Secret encrypted and Saved!', context);
  }

  @override
  Widget build(BuildContext context) {
    const List<String> pageTitles = [
      'Welcome', 'View Secrets', 'Encrypt Secret', 'Decrypt Secret', 'Token Generator'
    ];

    final List<Widget> pageContents = [
      HomePage(),
      ViewSecretsPage(listItems: _secrets),
      EncryptSecretPage(onSave: _addProfileData),
      DecryptPage(),
      TokenGeneratorPage(),
    ];

    return Scaffold(
      appBar: AppBar(
        title: Text(pageTitles[_selectedIndex]),
        centerTitle: true,
      ),
      drawer: Drawer(
        child: ListView(
          padding: EdgeInsets.zero,
          children: <Widget>[
            DrawerHeader(
              decoration: BoxDecoration(color: Theme.of(context).primaryColor),
              child: const Text('GoogleCTF\n2025', style: TextStyle(color: Colors.lightGreenAccent, fontSize: 24)),
            ),
            ListTile(
              leading: const Icon(Icons.home),
              title: const Text('Home'),
              onTap: () => _selectPage(0),
            ),
            ListTile(
              leading: const Icon(Icons.security_outlined),
              title: const Text('View Secrets'),
              onTap: () => _selectPage(1),
            ),
            ListTile(
              leading: const Icon(Icons.enhanced_encryption_outlined),
              title: const Text('Encrypt Secret'),
              onTap: () => _selectPage(2),
            ),
            ListTile(
              leading: const Icon(Icons.no_encryption_gmailerrorred_outlined),
              title: const Text('Decrypt Secret'),
              onTap: () => _selectPage(3),
            ),
            ListTile(
              leading: const Icon(Icons.casino),
              title: const Text('Token Generator'),
              onTap: () => _selectPage(4),
            ),
          ],
        ),
      ),
      body: pageContents[_selectedIndex],
    );
  }
}

