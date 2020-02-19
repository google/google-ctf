#!/usr/bin/env python
# -*- coding: utf-8 -*-

import BaseHTTPServer

class HealthzHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/healthz':
            self.send_response(404)
            self.send_header("Content-length", "0")
            self.end_headers()
            return

        content = 'err'
        try:
            with open('/tmp/healthz', 'r') as fd:
                content = fd.read().strip()
        except:
            pass
        self.send_response(200 if content == 'ok' else 400)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

httpd = BaseHTTPServer.HTTPServer(('', 8080), HealthzHandler)
httpd.serve_forever()
