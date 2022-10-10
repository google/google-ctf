import os
import validation
import persistent_state
import serialization_pb2
import serialize
from http import server
import json

def start(port):
    pid = os.fork()
    if pid != 0:
        return
    server_class = server.ThreadingHTTPServer
    handler_class = MyServer
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()

class MyServer(server.BaseHTTPRequestHandler):
    def do_GET(self):
        ps = get_persistent_state()
        ps = {
            "obtained_flags": {**ps.obtained_flags},
            "game_complete": ps.game_complete
        }
        self.send_response(200)
        self.send_header("Content-type", "text/json")
        self.end_headers()

        self.wfile.write(json.dumps(ps).encode("utf-8"))

def get_persistent_state():
    try:
        with open("./persistent_state", "rb") as f:
            save = f.read()
    except FileNotFoundError:
        ps = persistent_state.PersistentState()
        return ps

    save = serialization_pb2.SerializedPackage.FromString(save)
    ps = serialize.Deserialize(save, None)
    return ps
