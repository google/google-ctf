RES_INPUT = $(shell find ./resources)
GAME_SRC = $(shell find ./game/src/ -name "*.rs")
LIB_SRC = $(shell find ./libs/ -name "*.rs")

hx8.md: $(RES_INPUT) $(GAME_SRC) $(LIB_SRC)
	(docker images | grep mega) || docker build ./toolchain -t mega
	docker run --rm -t -v $(realpath ./):/src mega sh -c "cd /src/rom; ./.build.sh"

clean:
	(docker images | grep mega) || docker build ./toolchain -t mega
	docker run --rm -t -v $(realpath ./):/src mega sh -c "rm -rf /src/target.docker"
	rm -rf game/src/res/sprites/* game/src/res/maps/* game/src/res/palettes.rs game/src/res/tiles.rs

.PHONY: clean
