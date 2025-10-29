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
import 'helper.dart';


// A new page to show the details of a single entry.
class EntryDetailPage extends StatefulWidget {
  final SecretEntry entry;

  const EntryDetailPage({Key? key, required this.entry}) : super(key: key);

  @override
  _EntryDetailPageState createState() => _EntryDetailPageState();
}

class _EntryDetailPageState extends State<EntryDetailPage> {
  bool _isSecretVisible = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.entry.name),
        centerTitle: true,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min, // Make the card wrap its content
              children: [
                Text(
                  'Date: ${widget.entry.date}',
                  style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                Text(
                  'Name: ${widget.entry.name}',
                  style: const TextStyle(fontSize: 18),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Encrypted Secret:',
                  style: TextStyle(fontSize: 18),
                ),
                const SizedBox(height: 4),
                InkWell(
                  onTap: () {
                    setState(() {
                      _isSecretVisible = !_isSecretVisible;
                    });
                  },
                  child: Container(
                    padding: const EdgeInsets.symmetric(vertical: 8.0),
                    child: Row(
                      children: [
                        Expanded(
                          child: Text(
                            _isSecretVisible ? widget.entry.secret : '*******',
                            style: TextStyle(
                                fontSize: 16,
                                fontFamily: 'monospace',
                                backgroundColor: Colors.grey[800]),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Icon(
                          _isSecretVisible ? Icons.visibility_off : Icons.visibility,
                          color: Colors.grey,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                Center(
                  child: ElevatedButton(
                    onPressed: () {
                      Navigator.pop(context);
                    },
                    child: const Text('Back'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}


class ViewSecretsPage extends StatelessWidget {
  final List<SecretEntry> listItems;

  const ViewSecretsPage({Key? key, required this.listItems}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    if (listItems.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(16.0),
          child: Text(
            'No secrets have been added yet.',
            style: TextStyle(fontSize: 24, color: Colors.grey),
            textAlign: TextAlign.center,
          ),
        ),
      );
    }

    // Display the list of items.
    return ListView.builder(
      itemCount: listItems.length,
      itemBuilder: (context, index) {
        final item = listItems[index];
        return Card(
          margin: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
          child: ListTile(
            title: Text(
                '${item.date}\n'
                    'Name: ${item.name}'),
            trailing: const Icon(Icons.arrow_forward_ios),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => EntryDetailPage(entry: item),
                ),
              );
            },
          ),
        );
      },
    );
  }
}
