# Google CTF 2023 - pwn: write-flag-where writeup

In this task, we have a binary that, as we can deduce from its output, and confirm by reverse engineering, allows us to write the flag at any location in memory.

In the first version of the challenge, we are given the /proc/self/maps contents - so ASLR is not a problem.
The exploit is fairly simple - the binary will write the "Give me an address" message after every loop, and we can overwrite it flag, so that the server will send us the flag instead. Using gdb, we find the correct offset from the binary base, which we add to the one we get from the server:

```
$ nc localhost 1337
This challenge is not a classical pwn
In order to solve it will take skills of your own
An excellent primitive you get for free
Choose an address and I will write what I see
But the author is cursed or perhaps it's just out of spite
For the flag that you seek is the thing you will write
ASLR isn't the challenge so I'll tell you what
I'll give you my mappings so that you'll have a shot.
55cc14e9b000-55cc14e9c000 r--p 00000000 fe:01 1707638   [...]/chal
[...]

Give me an address and a length just so:
<address> <length>
And I'll write it wherever you want it to go.
If an exit is all that you desire
Send me nothing and I will happily expire
0x55cc14e9d198 123
CTF{testflag}
```
