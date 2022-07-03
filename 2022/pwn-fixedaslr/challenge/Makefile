CFLAGS_LOADER=\
    -Wall -Wextra \
    -masm=intel \
    -nostdlib -static \
    -fno-asynchronous-unwind-tables
CFLAGS_OBJ=\
    -Wall -Wextra \
    -c \
    -masm=intel \
    -nostdlib \
    -fno-asynchronous-unwind-tables \
    -fno-exceptions \
    -fPIC \
    -fstack-protector-all
# -Wl,--verbose

all:
	gcc loader.c ${CFLAGS_LOADER} -o loader
	echo 'Game file building disabled to not change offsets.'
	#gcc main.c ${CFLAGS_OBJ}
	#gcc syscalls.c ${CFLAGS_OBJ}
	#gcc guard.c ${CFLAGS_OBJ}
	#gcc basic.c ${CFLAGS_OBJ}
	#gcc game.c ${CFLAGS_OBJ}
	#gcc res.c ${CFLAGS_OBJ}
	#gcc debug.c ${CFLAGS_OBJ}
