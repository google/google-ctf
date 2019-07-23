#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2019 Google LLC
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
import binascii
import requests
import struct
import sys

HUB_ENDPOINT = '/SendIRCommand'

CMD_PING = 0x01

CMD_GETTEMP = 0x10
CMD_GETHUMIDITY = 0x11
CMD_GETCO2 = 0x12
CMD_GETSMOKEDETECTOR = 0x13

CMD_SETTIME = 0x20

CMD_SYSVER = 0x30

CMD_REPLY = 0x80


def crc8(data):
    # Expect a list of integer
    # LFSR calculation of CRC8-CCITT
    crc = 0
    for v in data:
        crc = crc ^ (v << 8)
        for i in range(8):
            if (crc & 0x8000):
                crc = crc ^ (0x1070 << 3)
            crc = crc << 1
    return (crc >> 8)


def send_command(host, command, arguments, expected_reply_len=None):
    if len(arguments) > 251:
        print('Argument too long.')
        sys.exit(1)

    packet = [0x55, len(arguments)+4, command, ] + list(arguments)
    checksum = crc8(packet)
    packet = packet + [checksum, ]
    packet = bytes(packet)
    packet_hex = binascii.hexlify(packet)

    # Send the request packet to the Hub to be transmitted to the smart clock
    # through 940nm IR at 1786bps
    req = requests.post('https://%s/%s'%(host, HUB_ENDPOINT), data=packet_hex)
    if req.status_code != requests.codes.ok:
        print('Hub returned error')
        sys.exit(1)
    reply = binascii.unhexlify(req.text)
    if len(reply) == 0:
        # It's offline
        print('Smart Clock is unreachable.')
        sys.exit(0)
    if len(reply)-1 != expected_reply_len and expected_reply_len is not None:
        print('Smart Clock returned an invalid response.')
        sys.exit(0)

    # Verify that the reply command is correct
    if reply[0] != command | CMD_REPLY:
        print('Invalid reply received')
        sys.exit(1)

    return reply[1:]


def main():
    parser = argparse.ArgumentParser(description='Smart Clock Client')
    parser.add_argument(
        '-p', '--ping', help='Ping the smart clock to see if it is online',
        action='store_true')
    parser.add_argument('-t', '--get-temperature',
                        help='Get the temperature sensor reading in the '
                             'smart clock', action='store_true')
    parser.add_argument('-u', '--get-humidity',
                        help='Get the humidity sensor reading in the '
                        'smart clock', action='store_true')
    parser.add_argument(
        '-c', '--get-co2', help='Get the CO2 sensor reading in the '
        'smart clock', action='store_true')
    parser.add_argument('-s', '--get-smoke-detector',
                        help='Get the smoke detector status in the smart '
                        'clock', action='store_true')
    parser.add_argument('-f', '--get-firmware-version',
                        help='Get the smart clock firmware version',
                        action='store_true')
    parser.add_argument('host', help='Hostname of the smart clock')
    parse_result = parser.parse_args()

    if parse_result.ping:
        ping_payload = b'GoogleCTF FTW!!11!'
        reply = send_command(
            parse_result.host, CMD_PING, ping_payload, len(ping_payload))
        for i in range(len(ping_payload)):
            # The calculation is done on the clock's side,
            # just some sanity check
            if ping_payload[i] != reply[i] ^ (0x12+i):
                print('Smart Clock returned an incorrect response.')
                sys.exit(0)

        # If we get here it's gotta be good.
        print('Pong! Smart Clock is online.')

    if parse_result.get_temperature:
        reply = send_command(parse_result.host, CMD_GETTEMP, b'', 2)
        temperature = (reply[0] << 8 | reply[1])/10.0
        print('The Temperature is %.1f' % temperature)

    if parse_result.get_humidity:
        reply = send_command(parse_result.host, CMD_GETHUMIDITY, b'', 2)
        humidity = (reply[0] << 8 | reply[1])/10.0
        print('The Humidity is %.1f%%' % humidity)

    if parse_result.get_co2:
        reply = send_command(parse_result.host, CMD_GETCO2, b'', 2)
        co2 = (reply[0] << 8 | reply[1])/10.0
        print('The CO2 concentration is %.1fppm' % co2)

    if parse_result.get_smoke_detector:
        reply = send_command(
            parse_result.host, CMD_GETSMOKEDETECTOR, b'', 1)
        if reply[0] == 0:
            print('No smoke detected')
        else:
            print('Smoke detected')

    if parse_result.get_firmware_version:
        reply = send_command(parse_result.host, CMD_SYSVER, b'', 2)
        print('Smart Clock firmware version %d.%d' % (reply[0], reply[1]))


if __name__ == '__main__':
    main()
