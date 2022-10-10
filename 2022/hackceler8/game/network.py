# Copyright 2022 Google LLC
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
import os
from abc import ABC
import json
import queue
import socket
import ssl
import struct
import sys
import threading
from datetime import datetime
from typing import Dict
from typing import Optional

from google.protobuf import message

import environ
import serialization_pb2
import serialize
import utils
import settings

message_callbacks: Dict = {}
_DEFAULT_MESSAGE_CALLBACKS_ENTRY = [bytes, None]

# Sentinel type to indicate that an object should be serialized/deserialized
# as JSON. Do not actually instantiate.
class JSON(ABC):
    pass


def register(message_name, message_type=bytes, func=None):
    return _register(message_callbacks, message_name, message_type, func)


def _register(message_callbacks, message_name, message_type=bytes, func=None):
    if type(message_name) != bytes:
        message_name = message_name.encode("utf-8")

    if message_name in message_callbacks:
        raise RuntimeError(f"message_name {message_name} already registered.")

    message_callbacks[message_name] = [message_type, None]

    def decorator(func2):
        message_callbacks[message_name][1] = func2
        return func2

    if func is None:
        return decorator
    else:
        decorator(func2)


def _serialize_for_network(obj):
    if isinstance(obj, bytes):
        return obj
    elif isinstance(obj, str):
        return obj.encode("utf-8")
    elif isinstance(obj, int):
        return utils.serialize_int(obj)
    elif isinstance(obj, float):
        return struct.pack("<d", obj)
    elif isinstance(obj, bool):
        return b'\x01' if obj else b'\x00'
    elif isinstance(obj, serialize.SerializableBase):
        return serialize.Serialize(obj).SerializeToString()
    elif isinstance(obj, message.Message):
        return obj.SerializeToString()
    else:
        raise RuntimeError(f"Cannot serialize unsupported type {type(obj)}")


def _deserialize_for_network(typ, obj):
    if issubclass(typ, bytes):
        return obj
    if issubclass(typ, str):
        return obj.decode("utf-8")
    if issubclass(typ, int):
        return utils.deserialize_int(obj)
    if issubclass(typ, float):
        return struct.unpack("<d", obj)[0]
    if issubclass(typ, bool):
        return obj != b'\x00'
    if issubclass(typ, serialize.SerializableBase):
        ret = serialization_pb2.SerializedPackage()
        ret.ParseFromString(obj)
        return serialize.Deserialize(ret)
    if issubclass(typ, message.Message):
        ret = typ()
        ret.ParseFromString(obj)
        return ret
    else:
        raise RuntimeError(f"Cannot deserialize unsupported type {type(obj)}")


def _get_cert_cn(cert) -> str:
    for sub in cert.get('subject', ()):
        for k, v in sub:
            if k == 'commonName':
                return v


def wrap_and_handshake(sock, server: bool, my_cert: str, expected_client: Optional[str] = None):
    if server:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile='ca.crt')
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='ca.crt')
        context.check_hostname = False  # we don't have a meaningful value to check
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(f'{my_cert}.crt', f'{my_cert}.key')
    ssl_socket: ssl.SSLSocket = context.wrap_socket(sock, server_side=server)
    print('SSL:', ssl_socket.cipher())
    peer = ssl_socket.getpeercert()
    print('SSL peer:', peer)
    cn = _get_cert_cn(peer)
    print('CN:', cn)
    if server:
        assert expected_client
        if cn != expected_client:
            raise Exception('invalid client: expected %s, got %s' % (expected_client, cn))
    else:
        if not (cn == 'prod-server' or os.environ.get('UNTRUSTED_SERVER') == '1'):
            raise Exception(f'server CN {cn} is not allowed')
    return ssl_socket


LOG_RECV_MARKER = b'\x00'
LOG_SEND_MARKER = b'\x01'

class NetworkConnection:
    def __init__(self, sock, server, traffic_log_file=None):
        self.socket = sock
        self._message_callbacks: Dict = {}
        self._message_queue: queue.Queue = queue.Queue(maxsize=100)
        self._recv_thread = threading.Thread(target=self._recv_thread_func, daemon=True, name="NetworkConnection recv thread.")
        self._recv_thread.start()
        self._traffic_log_file = traffic_log_file
        self._server = server

    def _send_bytes(self, b):
        data = len(b).to_bytes(4, "little") + b

        if self._traffic_log_file:
            timestamp = int(datetime.utcnow().timestamp()).to_bytes(4, "little")
            self._traffic_log_file.write(LOG_SEND_MARKER + timestamp + data)

        self.socket.sendall(data)

    def _get_registration(self, message_name):
        entry = self._message_callbacks.get(message_name, None)
        if entry is None:
            entry = message_callbacks.get(message_name, _DEFAULT_MESSAGE_CALLBACKS_ENTRY)
        return entry

    def send(self, message_name, data):
        if type(message_name) != bytes:
            message_name = message_name.encode("utf-8")

        message_type, _ = self._get_registration(message_name)

        if message_type == type(None):
            if data is not None:
                raise RuntimeError(f"Message {message_name} is none-type (no payload), but payload {data} was provided.")
            self._send_bytes(message_name)
            return

        if isinstance(data, utils.Proxy):
            data = data.__dict__['_wrapped']

        if message_type == JSON:
            data = json.dumps(data, ensure_ascii=False).encode("utf-8")
        elif not isinstance(data, message_type):
            if id(self._get_registration(message_name)) == id(_DEFAULT_MESSAGE_CALLBACKS_ENTRY):
                raise RuntimeError(
                    f"Message {message_name} is unregistered and was passed non-bytes type {type(data)}.")
            raise RuntimeError(
                f"Message {message_name} was passed wrong type. Expected {message_type}, got {type(data)}.")
        else:
            data = _serialize_for_network(data)

        assert isinstance(data, bytes)

        self._send_bytes(message_name)
        self._send_bytes(data)

    def _recvall(self, size: int):
        ret = b''
        while len(ret) < size:
            tmp = self.socket.recv(size)
            if not tmp:
                raise socket.error("Network disconnected.")
            ret += tmp
        return ret

    def _recv_bytes(self):
        size_bytes = self._recvall(4)
        size = int.from_bytes(size_bytes, "little")
        ret = self._recvall(size)

        if self._traffic_log_file:
            timestamp = int(datetime.utcnow().timestamp()).to_bytes(4, "little")
            self._traffic_log_file.write(LOG_RECV_MARKER + timestamp + size_bytes + ret)

        return ret

    def _recv_one(self):
        message_name = self._recv_bytes()
        message_type, cb = self._get_registration(message_name)
        if message_type == type(None):
            return (message_name, None, cb)

        message = self._recv_bytes()

        if cb is None and self._server:
            raise RuntimeError(f"Message {message_name} has no registered callback.")

        if message_type == JSON:
            message = json.loads(message.decode("utf-8"))
        else:
            message = _deserialize_for_network(message_type, message)
        return (message_name, message, cb)

    def _recv_thread_func(self):
        try:
            while True:
                tup = self._recv_one()
                self._message_queue.put(tup)
        except BaseException as e:
            self._message_queue.put(("__exception__", e, None))

    def recv_one(self):
        message_name, message, cb = self._message_queue.get()
        if message_name == "__exception__":
            raise message
        return (message_name, message, cb)

    def recv_one_nowait(self):
        try:
            tup = self._message_queue.get_nowait()
        except queue.Empty:
            return None
        if tup[0] == "__exception__":
            raise tup[1]
        return tup

    def register(self, message_name: str, message_type: type = bytes, func=None):
        _register(self._message_callbacks, message_name, message_type, func)

    def run(self):
        while True:
            message_name, message, cb = self.recv_one()
            if cb is None:
                raise RuntimeError(f"Message {message_name} has no registered callback.")
            cb(message)
