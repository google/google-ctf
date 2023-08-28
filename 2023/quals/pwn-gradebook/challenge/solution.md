# Solution

The code parses gradebook files by mmapping them and using as a struct. This
makes it vulnerable to some TOCTOU issues, since players can overwrite the file
by opening two connections (after the first one already passed some sanity
checks).

Exploit code is in `exploit.py`.
