// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const readline = require('node:readline');
const parse = require('bash-parser');
const { exec } = require("child_process");

const check = ast => {
  if (typeof(ast) === 'string') {
    return true;
  }
  for (var prop in ast) {
    if (prop === 'type' && ast[prop] === 'Redirect') {
      return false;
    }
    if (prop === 'type' && ast[prop] === 'Command') {
      if (ast['name'] && ast['name']['text'] && ast['name']['text'] != 'echo') {
        return false;
      }
    }
    if (!check(ast[prop])) {
      return false;
    }
  }
  return true;
};

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question(`I like scripts with echo. What's your favorite bash script? `, cmd => {
  const ast = parse(cmd);
  if (!ast.type === 'Script') {
    rl.write('This is not even a script!');
    rl.close();
    return;
  }
  if (!check(ast)) {
    rl.write('Hacker detected! No hacks, only echo!');
    rl.close();
    return;
  }
  exec(cmd, { shell: '/bin/bash' }, (error, stdout, stderr) => {
    rl.write(stdout);
    rl.close();
  });
});

