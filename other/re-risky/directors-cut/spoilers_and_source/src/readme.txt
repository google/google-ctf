Non-standard deps:
  https://github.com/riscv/riscv-gcc

1. To rebuild:
Note: Don't rebuild unless you really need too.

Run go.sh to rebuild everything.

You might have to fix the hardcoded offsets in loader.py.template if you make
changes or recompile risc-emu.*. In such case look for the following lines in
the go.sh output:

+ objdump -x riscv-emu-standalone
...
start address 0x0000000042000900
              ^^^^^^^^→1←^^^^^^^

Program Header:
LOAD off    0x0000000000001000 vaddr 0x0000000042000000 paddr 0x0000000042000000 align 2**12
            ^^^^^^^^→2←^^^^^^^       ^^^^^^^^→3←^^^^^^^

     filesz 0x0000000000000a78 memsz 0x0000000000000a78 flags r-x
            ^^^^^^^^→4←^^^^^^^

LOAD off    0x0000000000001a78 vaddr 0x0000000042001a78 paddr 0x0000000042001a78 align 2**12
            ^^^^^^^^→5←^^^^^^^       ^^^^^^^^→6←^^^^^^^

     filesz 0x0000000000003028 memsz 0x0000000000004028 flags rw-
            ^^^^^^^^→7←^^^^^^^
...

And make changes to the following places in loader.py.template (note the comments):

text = mmap(→3←, →4 padded to page size←, 7, 0x32, -1, 0)
data = mmap(→5 with bottom 12 bits cleared←, →7 with 2-3 pages of excess←, 7, 0x32, -1, 0)

"PROG_TEMPLATE"

text_sz = →4←
data_sz = →7←

memcpy(text, create_string_buffer(prog[→2←:→2←+text_sz]), text_sz)
memcpy(data + text_sz, create_string_buffer(prog[→2←+text_sz:→2←+text_sz+data_sz]), data_sz)

func_type = CFUNCTYPE(c_int, c_void_p)
func = cast(→1←, func_type)

After making these changes run go.sh again.

2. To change the flag:
Edit gen_mixer.py (the flag variable there). The new flag must not have more
than 31 bytes and should consist of [a-zA-Z0-9{}] characters only (if you need
more, just change the alphabet in risky.py.template).
Then run gen_mixer.py and go.sh.
You might need to change the flag in some other places for the tests to work.

