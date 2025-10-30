CC=gcc
C_FLAGS=-Wall -Werror -std=c17 -Iinc/
LD_FLAGS=
EXE=build/multiarch

INPUT_FILES=${wildcard src/*.c}
TARGET_OBJS=$(patsubst src/%.c,build/%.o,$(INPUT_FILES))

.PHONY: all
all: $(EXE)

$(EXE): $(TARGET_OBJS)
	$(CC) $(C_FLAGS) -o $@ $^ $(LD_FLAGS)

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(C_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf build

.PHONY: debug
debug: C_FLAGS+=-DDEBUG -ggdb
debug: $(EXE);

.PHONY: rel
rel: C_FLAGS+=-O1
rel: $(EXE)
	strip $(EXE)