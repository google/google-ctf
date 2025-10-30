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

class HomePage extends StatelessWidget {
  const HomePage({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: <Widget>[
          Icon(
            Icons.lock_outline,
            size: 200,
            color: Colors.lightGreenAccent,
          ),
          Text(
            'Fluffy',
            style: TextStyle(fontSize: 36, color: Colors.lightGreenAccent),
            textAlign: TextAlign.center,
          ),
          SizedBox(height: 20),
          Text(
            'The App to protect your secrets',
            style: TextStyle(fontSize: 24, color: Colors.lightGreenAccent),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
}
