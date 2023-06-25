all: oldschool

oldschool:
	g++ oldschool.c -o oldschool -lncurses -lform \
	-D PRNG_SEED=123456 -m32 -s # -g --static

clean:
	rm -f oldschool

