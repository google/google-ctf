#!/usr/bin/python -u

# Copyright 2021 Google LLC
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

import random
import string
import time

from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

max_queries = 150
query_delay = 10

passwords = [bytes(''.join(random.choice(string.ascii_lowercase) for _ in range(3)), 'UTF-8') for _ in range(3)]
flag = open("flag.txt", "rb").read()

def menu():
    print("What you wanna do?")
    print("1- Set key")
    print("2- Read flag")
    print("3- Decrypt text")
    print("4- Exit")
    try:
        return int(input(">>> "))
    except:
        return -1

print("Welcome!\n")

key_used = 0

for query in range(max_queries):
    option = menu()

    if option == 1:
        print("Which key you want to use [0-2]?")
        try:
            i = int(input(">>> "))
        except:
            i = -1
        if i >= 0 and i <= 2:
          key_used = i
        else:
          print("Please select a valid key.")
    elif option == 2:
        print("Password?")
        passwd = bytes(input(">>> "), 'UTF-8')

        print("Checking...")
        # Prevent bruteforce attacks...
        time.sleep(query_delay)
        if passwd == (passwords[0] + passwords[1] + passwords[2]):
            print("ACCESS GRANTED: " + flag.decode('UTF-8'))
        else:
            print("ACCESS DENIED!")
    elif option == 3:
        print("Send your ciphertext ")

        ct = input(">>> ")
        print("Decrypting...")
        # Prevent bruteforce attacks...
        time.sleep(query_delay)
        try:
            nonce, ciphertext = ct.split(",")
            nonce = b64decode(nonce)
            ciphertext = b64decode(ciphertext)
        except:
            print("ERROR: Ciphertext has invalid format. Must be of the form \"nonce,ciphertext\", where nonce and ciphertext are base64 strings.")
            continue

        kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1, backend=default_backend())
        key = kdf.derive(passwords[key_used])
        try:
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)
        except:
            print("ERROR: Decryption failed. Key was not correct.")
            continue

        print("Decryption successful")
    elif option == 4:
        print("Bye!")
        break
    else:
        print("Invalid option!")
    print("You have " + str(max_queries - query) + " trials left...\n")

