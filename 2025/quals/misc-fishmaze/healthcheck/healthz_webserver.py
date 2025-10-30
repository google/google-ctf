#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import http.server

class HealthzHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/healthz':
            self.send_response(404)
            self.send_header("Content-length", "0")
            self.end_headers()
            return

        content = b'err'
        try:
            with open('/tmp/healthz', 'rb') as fd:
                content = fd.read().strip()
        except:
            pass
        self.send_response(200 if content == b'ok' else 400)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

httpd = http.server.HTTPServer(('', 45281), HealthzHandler)
httpd.serve_forever()
