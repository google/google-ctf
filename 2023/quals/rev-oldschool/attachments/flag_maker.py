#!/usr/bin/env python3
# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# GCTF'23 - Old School - Flag Maker
import hashlib

# Find the passwords for the following 50 usernames, substitute them inside the pairs,
# and then run the script to get the flag.
pairs = [
  ('gdwAnDgwbRVnrJvEqzvs', '{password}'),
  ('ZQdsfjHNgCpHYnOVcGvr', '{password}'),
  ('PmJgHBtIpaWNEMKiDQYW', '{password}'),
  ('OAmhVkxiUjUQWcmCCrVj', '{password}'),
  ('ALdgOAnaBbMwhbXExKrN', '{password}'),
  ('tqBXanGeFuaRSMDmwrAo', '{password}'),
  ('etTQMfSiRlMbNSuEOFZo', '{password}'),
  ('wceLFjLkBstBfQTtwnmv', '{password}'),
  ('rBiaRSHGLToSvIAQhZIs', '{password}'),
  ('ackTeRoASCkkkRUIBjmX', '{password}'),
  ('UBFLQMizCtLCnnOjaLMa', '{password}'),
  ('UwiBcAZEAJHKmZSrLqTB', '{password}'),
  ('oYlcWeZwpEEejIGuCHSU', '{password}'),
  ('txWHHXTtBXbckmRPxgCx', '{password}'),
  ('mhPdqEbAligcqQCsHLGl', '{password}'),
  ('UsIdCFPOqrXwsSMoqfIv', '{password}'),
  ('OdSAfswQJnMyjOlqpmqJ', '{password}'),
  ('eNKVZRlVwQCxWzDvUrUW', '{password}'),
  ('dUVNMmEPDxRIdVRXzbKa', '{password}'),
  ('iMBkfiyJxewhnvxDWXWB', '{password}'),
  ('xlQgeOrNItMzSrkldUAV', '{password}'),
  ('UPEfpiDmCeOzpXeqnFSC', '{password}'),
  ('ispoleetmoreyeah1338', '{password}'),
  ('dNcnRoRDFvfJbAtLraBd', '{password}'),
  ('FKBEgCvSeebMGixUVdeI', '{password}'),
  ('DfBrZwIrsHviSIbenmKy', '{password}'),
  ('OvQEEDVvxzZGSgNOhaEW', '{password}'),
  ('iNduNnptWlmAVsszvTIZ', '{password}'),
  ('GvTcyPNIUuojKfdqCbIQ', '{password}'),
  ('noAJKHffdaRrCDOpvMyj', '{password}'),
  ('rAViEUMTbUByuosLYfMv', '{password}'),
  ('YiECebDqMOwStHZyqyhF', '{password}'),
  ('phHkOgbzfuvTWVbvRlyt', '{password}'),
  ('arRzLiMFyEqSAHeemkXJ', '{password}'),
  ('jvsYsTpHxvXCxdVyCHtM', '{password}'),
  ('yOOsAYNxQndNLuPlMoDI', '{password}'),
  ('qHRTGnlinezNZNUCFUld', '{password}'),
  ('HBBRIZfprBYDWLZOIaAd', '{password}'),
  ('kXWLSuNpCGxenDxYyalv', '{password}'),
  ('EkrdIpWkDeVGOSPJNDVr', '{password}'),
  ('pDXIOdNXHhehzlpbJYGs', '{password}'),
  ('WMkwVDmkxpoGvuLvgESM', '{password}'),
  ('aUwdXCDDUWlPQwadOliF', '{password}'),
  ('WmlngotWTsikaXRDakbp', '{password}'),
  ('thrZhzSRBzJFPrxKmetr', '{password}'),
  ('TcurEDzLjepMrNwspPqd', '{password}'),
  ('SScTJRokTraQbzQpwDTR', '{password}'),
  ('PObUeTjQTwEflLQtPOJM', '{password}'),
  ('LUDPGXGvuVFAYlMTTowZ', '{password}'),
  ('UlTVDrBlCmXmFBmwLLKX', '{password}'),
]

print('CTF{' + hashlib.sha1(b'|'.join(f'{u}:{p}'.encode('utf-8') for u, p in pairs)).hexdigest() + '}')
