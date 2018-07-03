/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

const fs = require('fs'); // the builtin

function load(fileName) {
  // If it's not a reasonable charset or there's .. inside, throw
  if (!fileName.match(/^[/\-\_\.\d\w]+$/) || fileName.match(/\.\./)) {
    throw new Error(`FS abuse detected when trying to load ${file}`);
  }
  return String(fs.readFileSync('./' + fileName));
}

module.exports = {
  load:load,
};
