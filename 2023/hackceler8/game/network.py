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

import logging
import socket
import ssl
import struct


def perform_ssl_handshake(sock, cert, is_server, expected_cn=None):
    logging.debug(f"Performing SSL handshake, cert={cert}")
    if is_server:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile='../ca/CA-devel.crt')
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='../ca/CA-devel.crt')
        context.check_hostname = False

    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(f'{cert}.crt', f'{cert}.key')
    try:
        ssl_sock = context.wrap_socket(sock, server_side=is_server)
    except ssl.SSLError:
        logging.exception("SSL handshake failed")
        sock.close()
        return None

    if not is_server:
        return ssl_sock

    # Server, validate CN
    if expected_cn is None:
        logging.warning("Allowing any client cert CN")
        return ssl_sock

    for subj in ssl_sock.getpeercert().get('subject', ()):
        for k, v in subj:
            if k == 'commonName' and v == expected_cn:
                logging.info(f"Got valid certificate for {v}")
                return ssl_sock

    return None


class ListeningSocket:
    def __init__(self, sock, expected_cn=None, **kwargs):
        self.socket = sock
        self.kwargs = kwargs
        self.expected_cn = expected_cn

    def accept(self):
        s, addr = self.socket.accept()

        # TODO: Configurable SSL cert path
        s = perform_ssl_handshake(s, "../ca/dev-server", is_server=True, expected_cn=self.expected_cn)

        if not s:
            raise Exception("Authentication failure")

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
    def create_client(cls, address, port, cert, **kwargs):
        assert 'server' not in kwargs
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        x = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, x * 32)

        try:
            s.connect((address, port))
            s = perform_ssl_handshake(s, cert, is_server=False)
            if not s:
                logging.critical("SSL handshake failed")
                return None
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

