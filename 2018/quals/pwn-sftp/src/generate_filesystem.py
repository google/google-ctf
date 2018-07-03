#! /usr/bin/python

# Copyright 2018 Google LLC
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

def encode(name, data, key):
	output = 'size_t {}_data_size = {};\n'.format(name, len(data))
	output += 'char {}_data[] = {{'.format(name)
	i = 0
	for byte in data:
		if i % 13 == 0:
			output += '\n  '
		output += '0x{:02x}, '.format(ord(byte) ^ key)
		i += 1
	output += '\n};\n'
	return output


with open('sftp.c', 'r') as tmp:
	output = ''
	output += encode('flag', 'Nice try ;-)', 0x89)
	output += '\n'
	output += encode('sftp', tmp.read(), 0x37)
	output += '''
char root_bytes[sizeof(directory_entry) + sizeof(entry*)];

void __attribute__((constructor)) service_setup() {
  root = (directory_entry*)root_bytes;
  root->entry.parent_directory = NULL;
  strcpy(root->entry.name, "home");
  root->child_count = 1;
  memset(root->child, 0, sizeof(entry*));

  pwd = root;
  pwd = new_directory(user_name);

  file_entry* flag = new_file("flag");
  flag->size = flag_data_size;
  flag->data = malloc(flag_data_size);
  memcpy(flag->data, flag_data, flag_data_size);
  for (size_t i = 0; i < flag->size; ++i) {
    flag->data[i] ^= 0x89;
  }

  new_directory("src");
  file_entry* sftp = new_file("src/sftp.c");
  sftp->size = sftp_data_size;
  sftp->data = malloc(sftp_data_size);
  memcpy(sftp->data, sftp_data, sftp_data_size);
  for (size_t i = 0; i < sftp->size; ++i) {
    sftp->data[i] ^= 0x37;
  }
}
'''

	print output

