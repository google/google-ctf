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

import argparse
import logging
import json
import socket

import ludicer_gui
import network
import log
import pow


def solve_pow(sock):
    recv_until(sock, b'python3 ')
    recv_until(sock, b' solve ')
    data = recv_until(sock, b'\n')
    recv_until(sock, b'Solution? ')
    solution = pow.solve_challenge(data.decode('ascii')[:-1])
    sock.sendall(solution.encode()+b'\n')
    recv_until(sock, b'Correct\n')


def recv_until(s, d):
    buf = b''
    while not buf.endswith(d):
      buf += s.recv(1)
    return buf


def main():
    parser = argparse.ArgumentParser(prog='client', parents=[log.get_argument_parser()])
    parser.add_argument('hostname', nargs='?', default='localhost', help='Server address')
    parser.add_argument('port', nargs='?', type=int, default=8888, help='Server port')
    parser.add_argument('--standalone', action='store_true', default=False, help='Run locally (without connecting to a dedicated server)')
    parser.add_argument('--nopow', action='store_true', default=False, help='Skip computing the proof of work')

    args = parser.parse_args()
    log.setup_logging(args, file_prefix='client')

    logging.getLogger("arcade").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)

    net = None
    if not args.standalone:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        x = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, x * 32)

        try:
            s.connect((args.hostname, args.port))
            if not args.nopow:
              solve_pow(s)
            net = network.NetworkConnection(s)
        except ConnectionError:
            logging.fatal(f'Unable to connect to {args.hostname}:{args.port}. Connecting to server failed, pass --standalone if you want to run the game without a server.')
            raise SystemExit()
        except Exception as e:
            logging.critical(
                f"Unexpected exception when connecting to server: {str(e)}")
            raise

    window = ludicer_gui.Hackceler8(net)
    window.run()


if __name__ == "__main__":
    main()
