# NetSock
Note: If you're looking for netsock2 development files, look under the
[develop branch](https://github.com/gynvael/NetSock/tree/develop).

A simple networking (socket) library for C++ for Windows and systems
based on Linux kernel. It shouldn't really be used for any real stuff,
but it's OK for prototyping and small tools. Also, please note that
this library was created about 10 years ago and may contain bugs. A
lot of bugs. You have been warned :)

**NOTE**: It does `SO\_REUSEADDR` on every listening socket - you might
want to comment it out on a server where you're worried about other
apps binding to the same port.

See LICENSE file for licensing details.


