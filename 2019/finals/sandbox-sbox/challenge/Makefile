.PHONY: all clean
all: main helper

clean:
	$(RM) main helper helper.o main.o

helper: helper.o
	gcc -static helper.o -o helper
main: main.o
	gcc -static main.o -o main
