/**
 * Copyright 2023 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import cors from "@/server/middleware/cors";
import connectDb from "@/server/middleware/mongoose";
import verifyUser from "@/server/middleware/verifyUser";
const net = require('net');

const CHALL_DOMAIN = process.env.CHALL_DOMAIN || 'http://web-noteninja:1337';
const XSSBOT_DOMAIN = process.env.XSSBOT_DOMAIN || 'noteninja-xssbot';
const XSSBOT_PORT = process.env.XSSBOT_PORT || 1337;

const handler = async (req, res) => {
    await res.status(200).json({ message: "Reported to admin successfully!" })

    const url = `${CHALL_DOMAIN}/notes/${req.body.id}`
    const client = net.Socket();
    client.connect(XSSBOT_PORT, XSSBOT_DOMAIN);
    await new Promise(resolve => {
      client.on('data', data => {
        let msg = data.toString();
        if (msg.includes("Please send me")) {
          client.write(url + '\n');
          console.log(`sending to bot: ${url}`);
        }else{
          res.write(msg + '\n')
          if(msg.includes('Page: ')){
            res.write('Done.\n')
            res.end();
          }
        }
      });
    });

};

export default cors(verifyUser(connectDb(handler)));
