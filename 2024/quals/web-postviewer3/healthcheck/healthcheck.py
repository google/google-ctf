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

r1 = requests.get("http://localhost:1337/", headers={
      'host': 'postviewer3-web.2024.ctfcompetition.com'
})

r2 = requests.get("http://localhost:1337/product/shim.html", headers={
      'host': 'sbx-18x5q6vtj1fyhe2jt8xg92kuk292vnm5eh92n6jy13pbc5c32m.postviewer3-web.2024.ctfcompetition.com'
})

if "Postviewer v3" in r1.text and "Sandbox iframe" in r2.text:
      exit(0)

exit(1)
