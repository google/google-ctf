CC=clang-3.8
CFLAGS=-Wall -Wextra -std=gnu11 -lpthread -O0

all: primary

build: primary

primary: primary.c
	$(CC) primary.c $(CFLAGS) -o primary -ltcmalloc

generator: generator.c
	$(CC) generator.c $(CFLAGS) -o generator

clean:
	rm -f primary generator
