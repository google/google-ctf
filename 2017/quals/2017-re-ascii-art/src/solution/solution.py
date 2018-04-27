#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import os
import requests

os.sys.path.insert(0, '../proto')
os.sys.path.insert(0, '../server')
import string_encoding
import aart_message_pb2

def send_encoded_message(msg):
  serialized_msg = msg.SerializeToString()
  encoded_message = string_encoding.encode_string(serialized_msg).encode("hex")
  r = requests.post('http://' + server_address + '/', data = encoded_message)
  print "Received content: ", string_encoding.decode_string(r.content.decode("hex"))

if __name__ == "__main__":
  if len(os.sys.argv) != 2:
    print "Missing server address"
    exit()

  server_address = os.sys.argv[1]

  msg = aart_message_pb2.AArtMessage()
  msg.type = aart_message_pb2.AArtMessage.R_HELLO
  msg.client_id = 'A' * 32
  msg.content = "HELLO"

  send_encoded_message(msg)

  msg.type = aart_message_pb2.AArtMessage.R_OPERATION
  msg.content = "GET_FLAG"

  send_encoded_message(msg)
