GOD_MODE ?= 0
PROFILING ?= 0

CARGO_FEATURES =

CONTAINER_ENGINE := $(shell command -v podman 2> /dev/null || command -v docker 2> /dev/null)
ifeq ($(CONTAINER_ENGINE),)
	$(error "Please install either docker or podman and make sure it is in $$PATH")
endif

ifeq ($(GOD_MODE),1)
  CARGO_FEATURES += god_mode
endif
ifeq ($(PROFILING),1)
  CARGO_FEATURES += profiling
endif

.DEFAULT_GOAL := hx8.md

RES_INPUT = $(shell find ./resources)
GAME_SRC = $(shell find ./game/src/ -name "*.rs")
LIB_SRC = $(shell find ./libs/ -name "*.rs")

# Track Cargo features to force rebuilds when variables like GOD_MODE change.
# This file updates its timestamp only when the set of enabled features changes.
.features: FORCE
	@echo "$(CARGO_FEATURES)" | cmp -s - $@ || echo "$(CARGO_FEATURES)" > $@

FORCE:

hx8.md: $(RES_INPUT) $(GAME_SRC) $(LIB_SRC) .features
	($(CONTAINER_ENGINE) images -f reference="mega" | grep "mega") || $(CONTAINER_ENGINE) build ./toolchain -t mega
	$(CONTAINER_ENGINE) run --rm -e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) -e CARGO_FEATURES="$(CARGO_FEATURES)" -t -v "$(realpath ./)":/src mega sh -c "cd /src/rom; ./.build.sh"
	@if [ $$(readelf -S hx8.elf | gawk '/\.bss|\.data/ {sum += strtonum("0x"$$7)} END {print sum}') -gt 60000 ]; then \
		echo "bss/data segment exceed RAM size"; exit 1; fi;

clean:
	($(CONTAINER_ENGINE) images -f reference="mega" | grep "mega") || $(CONTAINER_ENGINE) build ./toolchain -t mega
	$(CONTAINER_ENGINE) run --rm -e HOST_UID=$(shell id -u) -e HOST_GID=$(shell id -g) -t -v "$(realpath ./)":/src mega sh -c "rm -rf /src/target.docker"
	rm -rf game/src/res/sprites/* game/src/res/maps/* game/src/res/palettes.rs game/src/res/tiles.rs


.PHONY: clean
