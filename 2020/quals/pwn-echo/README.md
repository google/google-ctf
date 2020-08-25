# Challenge
A select base echo server is exposed.
Teams can connect and talk to the server.
Each team should be getting a separate server instance.

# Solution
There is no check for max_fd < FD_SETSIZE.
This gives both a oob write and oob read.
Initialy 1021 connections, which will fit into fd_set, need to be created.

OOB u64 non-destructive read:
 - initialize 64 connections in a single select loop iteration
   - First stuff a lot (dozen MiBs) of data to a "delay" connections
     rd_buf without any newline.
   - For each u64 read send few extra KiBs of data to the "delay" connection
     This will cause extra/128 bytes scans of the entire rd_buf.
   - Do 64 async connects right after.
 - Connections corresponding to 1's will send "Hello [remote_fd_num]",
   0's will not send back anything.

Rewinding:
OOB connections need to be closed in order of descending remote_fd_num,
otherwise select might fail with EBADF as those are not covered by FD_ZERO.

OOB u64 write:
 - create 1 connection of a new 64-bit block
   - This will retain value of this bit and zero other 63 of the block
   - If it was non-zero and a zero first bit is desired:
     - Fill servers TCP write buffer:
       - Set a low SO_RCVBUF on the connection (needs to be done pre-connect)
       - Send a few megs of data ending with a newline and don't read it back
 - create other 63 connections of the 64-bit block
   - does not have to happen in 1 select-loop iteration - can be done 1-by-1
 - for each 1 bit of the desired value write "\n" to the corresponding
   connection

The rest is matter of creating a short ROP chain.
This needs to be less than 64 bytes otherwise stack cookie will be overriden
by readset.
Longer ROP is possible but requires fixing the cookie by filling TCP write
buffers of specific connections. It gets quite messy quickly.
Other solution is to leak stack address and split the ROP in two parts
- one placed somewhere in the read buffer.

