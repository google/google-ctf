.PHONY=all clean
all: jail init 
jail: CFLAGS=-std=c99
jail: jail.o util.o
init: CFLAGS=-std=c99
init: init.o util.o

clean:
	- rm init.o jail.o util.o jail init

tar:
	tar -cvf jail.tar *.c *.h Makefile
	cp jail.tar challenge/
