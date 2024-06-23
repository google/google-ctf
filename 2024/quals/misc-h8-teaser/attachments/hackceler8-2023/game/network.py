# Copyright 2023 Google LLC
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
import json
import time
import logging
import socket
import ssl
import struct
import threading


class ListeningSocket:
    def __init__(self, sock, **kwargs):
        self.socket = sock
        self.kwargs = kwargs

    def accept(self):
        s, addr = self.socket.accept()
        return (NetworkConnection(s, **self.kwargs), addr)


class NetworkConnection:
    @staticmethod
    def create_server(bind_address='0.0.0.0', port=8888, **kwargs):
        assert 'server' not in kwargs
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((bind_address, port))
            s.listen()
            return ListeningSocket(s, **kwargs)
        except Exception as e:
            logging.critical(e)
            s.close()
            # The server cannot continue without socket, reraise exception.
            raise

    @classmethod
    def create_client(cls, address, port, **kwargs):
        assert 'server' not in kwargs
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        x = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, x * 32)

        try:
            s.connect((address, port))
            return NetworkConnection(s, **kwargs)
        except ConnectionError:
            logging.critical(f'Unable to connect to {address}:{port}.')
            return None
        except Exception as e:
            logging.critical(
                f"Unexpected exception when connecting to server: {str(e)}")
            raise

    def __init__(self, sock):
        self.socket = sock

    @staticmethod
    def _recv(s, size: int):
        ret = b''
        while len(ret) < size:
            tmp = s.recv(size - len(ret))
            if not tmp:
                raise Exception("Network disconnected.")
            ret += tmp

        return ret

    def recv_one(self):
        size_bytes = NetworkConnection._recv(self.socket, 4)
        size = struct.unpack(">I", size_bytes)[0]
        ret = self._recv(self.socket, size)
        assert len(ret) == size, "Unexpected packet length"
        return ret

    def send_one(self, msg):
        self.socket.send(struct.pack(">I", len(msg)))
        self.socket.send(msg)
