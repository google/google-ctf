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
# GCTF'23 - Old School - Flag Maker (correct)
import hashlib

# Find the passwords for the following 50 usernames, substitute them inside the pairs,
# and then run the script to get the flag.
pairs = [
    ('gdwAnDgwbRVnrJvEqzvs', '2UTQS-QFE2D-Z3P9K-6CFM9-TRRH5'),
    ('ZQdsfjHNgCpHYnOVcGvr', 'W8HTX-Q3T4K-KJKXJ-3YAUG-PYN8V'),
    ('PmJgHBtIpaWNEMKiDQYW', 'RT7LH-X4B4P-6KZZL-PEE3Z-9RS9F'),
    ('OAmhVkxiUjUQWcmCCrVj', 'HMXWT-68GY7-2VPUJ-EDFLX-A2FWA'),
    ('ALdgOAnaBbMwhbXExKrN', 'AUPQR-7J7J6-S3EYS-5SLVJ-6R25D'),
    ('tqBXanGeFuaRSMDmwrAo', 'Y8S69-KWFPZ-GHZKT-52N37-8LES6'),
    ('etTQMfSiRlMbNSuEOFZo', 'YTZGK-2HE53-ZKSUU-WA2ML-PZSQJ'),
    ('wceLFjLkBstBfQTtwnmv', '6TY92-3KLSC-KEV5X-RY643-Z7VK8'),
    ('rBiaRSHGLToSvIAQhZIs', '26JCA-ACDYX-H8D5Y-ZBPMW-FUBXK'),
    ('ackTeRoASCkkkRUIBjmX', 'FAGD2-XUKFZ-EWT65-KXB8Y-SK93M'),
    ('UBFLQMizCtLCnnOjaLMa', 'EMXGH-S6J4L-W8NNC-9PLK7-Z5PBG'),
    ('UwiBcAZEAJHKmZSrLqTB', 'VHA9Q-4EWGV-RTFR3-LENAY-LGRGP'),
    ('oYlcWeZwpEEejIGuCHSU', 'HUSRJ-2AHUH-SYDUA-25Y7N-67GPB'),
    ('txWHHXTtBXbckmRPxgCx', 'PWWZ6-8VZKS-RX23E-Y6MDB-5BRHY'),
    ('mhPdqEbAligcqQCsHLGl', 'ZXER8-3PR65-UQHUT-VR885-2X4V8'),
    ('UsIdCFPOqrXwsSMoqfIv', 'H2C72-ECRQD-FTRQ4-JSCGX-H8CLR'),
    ('OdSAfswQJnMyjOlqpmqJ', 'RH6HX-HESDA-6MW6Q-2EBF9-EJ55L'),
    ('eNKVZRlVwQCxWzDvUrUW', 'DX89R-3PQSR-4JMD4-J3EKC-3YS9K'),
    ('dUVNMmEPDxRIdVRXzbKa', 'X2GZZ-JLNPN-RDRH6-29VMS-SUXVK'),
    ('iMBkfiyJxewhnvxDWXWB', 'UGZVX-W6MMM-XW6AU-9EKYP-NEFW8'),
    ('xlQgeOrNItMzSrkldUAV', '4ZH84-EQF2F-232HA-GNNS8-U5YUT'),
    ('UPEfpiDmCeOzpXeqnFSC', 'N9LZJ-8WEF7-DKHTR-NBSLS-8V2DV'),
    ('ispoleetmoreyeah1338', 'D78UE-UJF6Y-VLYWY-X2F8J-STPA3'),
    ('dNcnRoRDFvfJbAtLraBd', '34QTK-UTPD6-VRL42-BF9CC-64TX4'),
    ('FKBEgCvSeebMGixUVdeI', 'D3GAM-XED2M-MQ58F-8YAXL-7GRKU'),
    ('DfBrZwIrsHviSIbenmKy', 'QMA5K-CJ9LE-YEL7F-K233T-KAX9H'),
    ('OvQEEDVvxzZGSgNOhaEW', 'ZMR72-XKVBF-PLQ9D-SQ3DC-PZT2Q'),
    ('iNduNnptWlmAVsszvTIZ', '383MN-QTDF6-SXCML-HC3MF-AQJ26'),
    ('GvTcyPNIUuojKfdqCbIQ', '4ZCDD-6PR2H-Y22T6-C26ZU-XDQ3D'),
    ('noAJKHffdaRrCDOpvMyj', 'DM4PY-PV8T6-YX7ME-PQRU4-63CYR'),
    ('rAViEUMTbUByuosLYfMv', '3WYTQ-CKVP2-45ZYL-B84FY-JPEF4'),
    ('YiECebDqMOwStHZyqyhF', 'LB5DC-E34FE-5SR64-V9CPR-BGYGM'),
    ('phHkOgbzfuvTWVbvRlyt', 'AN45M-4XR8N-3TFP5-ZSLN8-EURYP'),
    ('arRzLiMFyEqSAHeemkXJ', 'RCZ6V-8PXWV-V4PAC-DVZ4S-SZSLE'),
    ('jvsYsTpHxvXCxdVyCHtM', 'AM2UM-RNWE3-PKAWJ-FBYHX-JD3ZQ'),
    ('yOOsAYNxQndNLuPlMoDI', 'AWBEY-KKQN3-T9HSA-8X9QQ-F97MR'),
    ('qHRTGnlinezNZNUCFUld', 'R5LPJ-8RFW3-K3U9E-GMC3K-DXWBH'),
    ('HBBRIZfprBYDWLZOIaAd', 'NLGEL-NF9ZR-PFBFY-2QQP9-U88ZB'),
    ('kXWLSuNpCGxenDxYyalv', 'EKYTX-77MN9-J7L3X-97CKN-DHNGS'),
    ('EkrdIpWkDeVGOSPJNDVr', 'D2FG8-JRLLL-SWLTQ-VX6GL-8C56A'),
    ('pDXIOdNXHhehzlpbJYGs', 'WW6S4-YKRXU-2GJ3A-AY83C-DJ9KR'),
    ('WMkwVDmkxpoGvuLvgESM', 'KAEAR-2H45E-DXMGG-AS66H-THT5Y'),
    ('aUwdXCDDUWlPQwadOliF', 'RAECM-QN7BG-A82TW-TD2P2-QNLAU'),
    ('WmlngotWTsikaXRDakbp', '9BR9R-8THRJ-VAQRY-4MVLR-948M2'),
    ('thrZhzSRBzJFPrxKmetr', 'ABD2P-7TG82-NUD2J-M3X4E-PYQPD'),
    ('TcurEDzLjepMrNwspPqd', '5YWRJ-RFSE3-DUM8L-VMBBE-K35HM'),
    ('SScTJRokTraQbzQpwDTR', 'J3793-WSSGE-S8GA7-YA6U3-5K9UW'),
    ('PObUeTjQTwEflLQtPOJM', 'M934Z-EKV2M-WUH7M-Y67LH-W3YDS'),
    ('LUDPGXGvuVFAYlMTTowZ', 'RAAY6-G6KXQ-M8JD5-YCQZ7-L5ZFR'),
    ('UlTVDrBlCmXmFBmwLLKX', 'MGWH5-9B4T5-F3AL4-NRF74-A23V3')
]

print('CTF{' + hashlib.sha1(b'|'.join(f'{u}:{p}'.encode('utf-8') for u, p in pairs)).hexdigest() + '}')
