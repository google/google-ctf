#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

import requests
import random
import string

def random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))

host = "http://localhost:1337"
username = "health_" +  random_string(7)
password = random_string(20)

try:
      response = requests.post(url = host + "/signup", headers={"content-type": "application/x-www-form-urlencoded"}, data="username="+username+"&password="+password+"&tier=blue&tier=gold")
      if(response.status_code != 200):
           exit(1)
      response = requests.post(url = host + "/login", data={"username":username, "password":password})
      if("Your tier is BLUE." in response.text):
           exit(0)
except requests.exceptions.ConnectionError:
     pass

exit(1)