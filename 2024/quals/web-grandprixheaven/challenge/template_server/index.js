/**
 * Copyright 2024 Google LLC
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

const http = require('http');

const templates = require('./templates');

const parseMultipartData  = (data, boundary) => {
  var chunks = data.split(boundary);
  // always start with the <head> element
  var processedTemplate = templates.head_start;
  // to prevent loading an html page of arbitrarily large size, limit to just 7 at a time
  let end = 7;
  if (chunks.length-1 <= end) {
    end = chunks.length-1;
  }
  for (var i = 1; i < end; i++) {
    // seperate body from the header parts
    var lines = chunks[i].split('\r\n\r\n')
    .map((item) => item.replaceAll("\r\n", ""))
    .filter((item) => { return item != ''})
    for (const item of Object.keys(templates)) {
        if (lines.includes(item)) {
            processedTemplate += templates[item];
        }
    }
  }
  return processedTemplate;
}


const reqHandler = function (req, res) {
  res.setHeader("Content-Type", "text/html");
  var result;
  if (req.method == 'POST') {
    var body = ''
    req.on('data', function(data) {
      body += data
    })
    req.on('end', function() {
      var boundary = '--' + req.headers['content-type'].split("boundary=")[1];
      result = parseMultipartData(body, boundary);
      res.end(result);
    })
  } else {
    res.writeHead(400);
    return res.end();
  }

};

const server = http.createServer(reqHandler);
server.listen(9999, () => {
  console.log('Server running at <http://localhost:9999/>');
});