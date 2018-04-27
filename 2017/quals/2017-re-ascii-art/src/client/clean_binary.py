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

# Ugly script to remove strings from the binary that were giving away too much
# information. This could be done better with strip commands at compile time.
import os

str_to_replace = """
/usr/local/google/home/pmbureau/Documents/code/2017-re-ascii-art/src/proto/aart_message.pb.cc
_ZN13StringEncoder14reverse_stringERSs
_ZN13StringEncoderC2Ev
_ZN13StringEncoder13decode_stringERSs
_ZN13StringEncoder18xor_with_last_charERSs
_ZN13StringEncoder13encode_stringERSs
_ZN13StringEncoder12invert_pairsERSs
_ZN13StringEncoder10decode_hexERKSsRSs
_ZN13StringEncoder15xor_with_lengthERSs
_ZN13StringEncoder19xor_with_first_charERSs
_ZN13StringEncoderC1Ev
_ZN13StringEncoder10encode_hexERKSsRSs
_ZN11AartMessage25AartMessageType_ARRAYSIZEE
_ZN11AartMessage16kTypeFieldNumberE
_ZN11AartMessage10descriptorEv
_ZN11AartMessage19AartMessageType_MINE
_ZTV11AartMessage
_ZNK11AartMessage8ByteSizeEv
_ZN11AartMessage14R_CAPABILITIESE
_ZN11AartMessageC1ERKS_
_ZN11AartMessageC2ERKS_
_ZN11AartMessageD0Ev
_ZN11AartMessage19AartMessageType_MAXE
_ZN11AartMessageD2Ev
_ZNK11AartMessage31SerializeWithCachedSizesToArrayEPh
_ZN11AartMessage5ClearEv
_ZN11AartMessageC1Ev
_ZN11AartMessageC2Ev
_ZN11AartMessage21InitAsDefaultInstanceEv
_ZN11AartMessage7R_HELLOE
_ZN11AartMessage17default_instance_E
_ZN11AartMessage4SwapEPS_
_ZNK11AartMessage3NewEv
_ZN11AartMessage16default_instanceEv
_ZN11AartMessage19kContentFieldNumberE
_ZN11AartMessageD1Ev
_ZN11AartMessage10SharedCtorEv
_ZNK11AartMessage13GetCachedSizeEv
_ZN11AartMessage10SharedDtorEv
_Z35AartMessage_AartMessageType_IsValidi
_ZN11AartMessage20kClientIdFieldNumberE
_ZNK11AartMessage24SerializeWithCachedSizesEPN6google8protobuf2io17CodedOutputStreamE
_Z12send_messageSsRK11AartMessageRS_
_ZN11AartMessage27MergePartialFromCodedStreamEPN6google8protobuf2io16CodedInputStreamE
_ZNK11AartMessage13IsInitializedEv
_ZN11AartMessage20R_OPERATION_RESPONSEE
_Z15process_messageRK11AartMessageRS_
_ZN11AartMessage11R_OPERATIONE
_ZNK11AartMessage11GetMetadataEv
_Z38AartMessage_AartMessageType_descriptorv
_ZNK11AartMessage13SetCachedSizeEi
_Z8HttpSendSsSsSsRSs
"""

input_filename = os.sys.argv[1]
content = open(input_filename, 'rb').read()

for s in str_to_replace.split("\n"):
  content = content.replace(s, len(s) * "\x00")

open("clean_" + input_filename, 'wb').write(content)