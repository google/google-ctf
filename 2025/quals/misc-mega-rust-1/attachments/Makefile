GAME_SRC = $(shell find ./game/src/ -name "*.rs")
LIB_SRC = $(shell find ./libs/ -name "*.rs")

sonk.md: $(GAME_SRC) $(LIB_SRC)
	(docker images | grep mega) || docker build ./toolchain -t mega
	docker run --rm -t -v $(realpath ./):/src mega sh -c "cd /src/rom; ./.build.sh"

podman: $(GAME_SRC) $(LIB_SRC)
	sudo podman run --rm -t -v $(realpath ./):/src mega sh -c "cd /src/rom; ./.build.sh"

clean:
	(docker images | grep mega) || docker build ./toolchain -t mega
	docker run --rm -t -v $(realpath ./):/src mega sh -c "rm -rf /src/target.docker"
	rm -f sonk.md sonk.elf

run: sonk.md
	mame genesis -cart $<

.PHONY: clean
