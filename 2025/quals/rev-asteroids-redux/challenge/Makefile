LDFLAGS=-static
TP := ../../third_party/rev-asteroids-redux

chal: chal.c
	gcc -std=c99 -Wall -Wextra -o $@ $< $(TP)/sha256.c $(TP)/aes.c -I. -I$(TP) -L$(TP) -lraylib -lm -lpthread -ldl -lrt -lX11 -O2
	strip $@
	mv chal ../attachments/playme
