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

const bot_addr = Deno.env.get("BOT_ADDR") || "localhost"; 
const bot_port = Deno.env.get("BOT_PORT") || 1337; 

export async function visit(url){
    console.log(bot_addr);
    const connection = await Deno.connect({
        port: bot_port,
        hostname: bot_addr,
    });

    const buf = new Uint8Array(100);
    await connection.read(buf);
    await connection.read(buf);
    var res = new TextDecoder().decode(buf);
    console.log(res)
    if (res.includes("Please send me a URL to open.")) {
        const request = new TextEncoder().encode(url+"\n");
        await connection.write(request);
        
    }
    connection.close();
}
