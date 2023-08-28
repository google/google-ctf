#!python3
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Helper program to generate packed binary & b64 encode
#
# !!NOT!! an intended attachement but checked in for reference and can be added to a solution folder
#

import sys
import ast
import struct
import base64

def parser_fatal(s):
	print(s)
	sys.exit(-2)

#struct ubf_packed {
#  int block_size;
#  char type;
#  short count;
#  short metadata_size;
#  // metadata[metadata_size]
#  // data[count]
#};

def serialize(typecode, entries):
	metadata = bytes()
	data = bytes()

	if typecode == 'b':
		for e in entries:
			data += struct.pack("<?", e)
	elif typecode == 'i':
		for e in entries:
			data += struct.pack("<i", e)
	elif typecode == 's':
		for e in entries:
			strdata = str.encode(e)
			print(strdata)
			metadata += struct.pack("<h", len(strdata))
			data += strdata
	else:
		parser_fatal('Invalid type code: ' + typecode)

	block_size = len(metadata) + len(data)

	block = struct.pack("<iBhh", block_size, ord(typecode), len(entries), len(metadata))
	block += metadata
	block += data

	return block


def pack(ubf_str):
	#print(ubf_str)
	serialized = bytes()
	for s in ubf_str.split(';'):
		if len(s) == 0:
			continue # final token usually

		s = s.strip()
		t = s[:s.find('[')]
		typecode = 'z'

		d = s[s.find('['):]
		if len(d) < 2 or d[0] != '[' or d[-1] != ']':
			parser_fatal('Invalid data')


		parsed_data = []
		if t.startswith('bool'):
			typecode = 'b'
			d = d[1:-1] # strip []
			for e in d.split(','):
				e = e.strip()
				if e == 'T':
					parsed_data.append(True)
				elif e == 'F':
					parsed_data.append(False)
				else:
					parser_fatal('Invalid bool data: ' + e)
		elif t.startswith('int'):
			typecode = 'i'
			d = d[1:-1] # strip []
			for e in d.split(','):
				e = e.strip()
				x = int(e)
				parsed_data.append(x)
		elif t.startswith('string'):
			typecode = 's'
			x = ast.literal_eval(d)
			for e in x:
				if not isinstance(e, str):
					parser_fatal('Non-string entry in string data: ' + e)
				parsed_data.append(e)
		else:
			parser_fatal('Invalid type: ' + s)

		serialized += serialize(typecode, parsed_data)

	return serialized


if len(sys.argv) < 2:
	print('Usage: ubf_pack.py <UBF string encoding>')
	sys.exit(-1)

data = pack(sys.argv[1])
f = open('test_ubf', 'wb')
f.write(data)
f.close()

print(base64.b64encode(data))
