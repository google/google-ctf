.PHONY: all
all: sandbox supervisor

supervisor: supervisor.o

sandbox: LDFLAGS=-static
sandbox: LDLIBS=-lcap -lseccomp
sandbox: sandbox.o
