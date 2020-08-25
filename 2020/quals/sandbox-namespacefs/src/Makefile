.PHONY: all
all: nsfs init

nsfs: LDLIBS=-lprotobuf -lcap
nsfs: LDFLAGS=-pthread
nsfs: nsfs.cc nsfs.pb.h nsfs.pb.o

nsfs.pb.o: nsfs.pb.cc

nsfs.pb.cc: nsfs.pb.h

nsfs.pb.h: nsfs.proto
	protoc --cpp_out=. nsfs.proto

init: LDFLAGS=-static
init: init.o
