/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

const net = require('net');
const XSSBOT_PORT = process.env.XSSBOT_PORT;
const XSSBOT_HOST = process.env.XSSBOT_HOST;
function visit(url) {
  console.log(url);
  const client = net.Socket();
  client.connect(XSSBOT_PORT, XSSBOT_HOST);
  client.on('data', data => {
    let msg = data.toString().trim();
    if (msg == "Please send me a URL to open.") {
      client.write(url+'\n');
      client.destroy();
    }
    console.log(msg);
  });
}
module.exports = {visit}
