#!/usr/bin/env bash
out="CA-${1:-devel}"
openssl req -x509 -sha256 -days 9001 -newkey rsa:2048 -keyout "$out".key -out "$out".crt -nodes
