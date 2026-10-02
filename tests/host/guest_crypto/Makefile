# Makefile
#
# Copyright (C) 2026 wolfSSL Inc.
#
# This file is part of wolfTrust.
#
# wolfTrust is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTrust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

# Shared guest PSA assertions run against the pinned wolfPSA/wolfCrypt stack.
ROOT := ../../..
CC ?= cc
BUILD_DIR ?= build
WOLFPSA := $(abspath $(ROOT)/lib/wolfPSA)
WOLFSSL := $(abspath $(ROOT)/lib/wolfSSL)
COMMON := $(ROOT)/tests/firmware/common
LIBRARY := $(abspath $(BUILD_DIR))/libwolfpsa.a
TEST := $(BUILD_DIR)/test_guest_crypto
CFLAGS := -std=c99 -O0 -g -Wall -Wextra -Werror -pedantic \
    -I$(COMMON) -isystem $(WOLFPSA) -isystem $(WOLFPSA)/wolfpsa $(EXTRA_CFLAGS)

.PHONY: all run clean compilers sanitize valgrind run-valgrind
all: $(TEST)

$(LIBRARY):
	$(MAKE) -C $(WOLFPSA) $(LIBRARY) CC="$(CC)" \
	    WOLFSSL_PATH="$(WOLFSSL)" USER_SETTINGS_PATH="$(WOLFPSA)" \
	    BUILD_DIR="$(abspath $(BUILD_DIR))/psa" LIBNAME="$@" \
	    WARNFLAGS="-Wall -Wextra" CFLAGS="-O0 -g $(EXTRA_CFLAGS)"

$(TEST): main.c $(COMMON)/psa_crypto_checks.c $(COMMON)/psa_crypto_checks.h $(LIBRARY)
	$(CC) $(CFLAGS) $(EXTRA_LDFLAGS) -o $@ main.c \
	    $(COMMON)/psa_crypto_checks.c $(LIBRARY) -lm

run: $(TEST)
	cd $(BUILD_DIR) && ./test_guest_crypto

compilers:
	$(MAKE) run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) run CC=clang BUILD_DIR=$(BUILD_DIR)/sanitize \
	    EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
	    EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind:
	$(MAKE) run-valgrind BUILD_DIR=$(BUILD_DIR)/valgrind

run-valgrind: $(TEST)
	cd $(BUILD_DIR) && valgrind --error-exitcode=1 --leak-check=full ./test_guest_crypto

clean:
	rm -rf $(BUILD_DIR)
