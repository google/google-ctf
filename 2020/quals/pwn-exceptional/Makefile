


.PHONY: clean all run test


all: out/out.elf exploit
	mkdir -p attachments
	cp out/out.elf attachments/exceptional

clean:
	rm -rf attachments out exploit

run: out/out.elf
	out/out.elf

test: out/out.elf exploit
	cat exploit | out/out.elf | grep CTF

out/out.cpp: scaffold.cpp asm.py asm/bintree.s
	mkdir -p out
	python3 asm.py asm/bintree.s scaffold.cpp out/out.cpp

out/out.elf: out/out.cpp
	g++ out/out.cpp -o out/out.elf
	strip out/out.elf
	# Even strip doesn't cut exception names, so...
	sed -i 's/EndLp_fun..../*6e_6f#70@65^/g' out/out.elf
	sed -i 's/RetEx/+-=_*/g' out/out.elf

exploit: pwn.py
	python3 pwn.py > exploit
