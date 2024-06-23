LDFLAGS=-static

chal: ../../third_party/misc-auxin2/uxn/uxn.c auxin2.tal
	gcc -DNDEBUG -Os -g0 -s ../../third_party/misc-auxin2/uxn/uxnasm.c -o ../../third_party/misc-auxin2/uxnasm
	../../third_party/misc-auxin2/uxnasm auxin2.tal auxin2.rom
