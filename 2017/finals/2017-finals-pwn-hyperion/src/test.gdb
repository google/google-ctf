! killall -9 hyperion_server
set disassembly-flavor intel
set environment HYPERION_FORK_SERVER=1
set follow-fork-mode child
set height 0
#break *0x402036
break *(Handler+0x20F9-0x20E8)
break *(Handler+0x27F5-0x20E8)
r
x/40gx $rsp+0x9600
c
x/40gx $rsp+0x9600
c
