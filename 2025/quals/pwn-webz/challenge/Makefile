# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# --- Compilers ---
# Compiler for regular builds
CC = clang

# --- Directories and Files ---
ZLIB_DIR = google-zlib
ZLIB_LIB = $(ZLIB_DIR)/libz.a

# --- Targets ---
TARGET = webz                     # Regular executable
ASAN_TARGET = webz_asan           # ASAN executable

# --- Flags ---
# Base flags (common)
BASE_CFLAGS = -Wall -Wextra -I$(ZLIB_DIR)/

# Flags for normal ASan build (debug symbols, ASan, maybe low optimization)
CFLAGS_STD = $(BASE_CFLAGS) -g -O0
LDFLAGS_STD = $(ZLIB_LIB) -lm # Add ASan linker flag and math lib

# Flags for normal ASan build (debug symbols, ASan, maybe low optimization)
CFLAGS_ASAN = $(BASE_CFLAGS) -g -fsanitize=address -O0
LDFLAGS_ASAN = -fsanitize=address $(ZLIB_LIB) -lm # Add ASan linker flag and math lib

# --- Build Rules ---

# Default target: Build the regular executable with ASan
all: $(TARGET)

# Build the regular executable (depends on zlib being built with standard ASan flags)
$(TARGET): webz.c build_zlib_std # Depends on the standard zlib build trigger
	@echo "--- Linking final target: $(TARGET) ---"
	$(CC) $(CFLAGS_STD) webz.c -o $(TARGET) $(LDFLAGS_STD)

# Build the regular executable (depends on zlib being built with standard ASan flags)
$(ASAN_TARGET): webz.c build_zlib_asan # Depends on the standard zlib build trigger
	@echo "--- Linking final target: $(ASAN_TARGET) ---"
	$(CC) $(CFLAGS_ASAN) webz.c -o $(ASAN_TARGET) $(LDFLAGS_ASAN)

# --- ZLIB Build Triggers ---

# Phony target to build google-zlib with standard ASan flags
.PHONY: build_zlib_std
build_zlib_std:
	@echo "--- Building google-zlib with ASan (standard compiler) ---"
	cd $(ZLIB_DIR) && \
	$(MAKE) distclean || true && \
	CC=$(CC) \
	CFLAGS="$(CFLAGS_STD)" \
	CXXFLAGS="$(CFLAGS_STD)" \
	./configure --static && \
	$(MAKE) -j$(shell nproc) libz.a
	@echo "--- Finished building google-zlib for standard ASan ---"

# Phony target to build google-zlib with standard ASan flags
.PHONY: build_zlib_asan
build_zlib_asan:
	@echo "--- Building google-zlib with ASan (standard compiler) ---"
	cd $(ZLIB_DIR) && \
	$(MAKE) distclean || true && \
	CC=$(CC) \
	CFLAGS="$(CFLAGS_ASAN)" \
	CXXFLAGS="$(CFLAGS_ASAN)" \
	LDFLAGS="-fsanitize=address" \
	./configure --static && \
	$(MAKE) -j$(shell nproc) libz.a
	@echo "--- Finished building google-zlib for standard ASan ---"

# --- Clean ---
.PHONY: clean
clean:
	rm -f $(TARGET) $(FUZZ_TARGET) $(ASAN_TARGET) test.webz  core.*
	# Also clean the zlib build directory
	cd $(ZLIB_DIR) && $(MAKE) clean || true

.PHONY: distclean
distclean: clean
	cd $(ZLIB_DIR) && $(MAKE) distclean || true
