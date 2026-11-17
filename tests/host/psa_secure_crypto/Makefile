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

ROOT    := ../../..
WOLFHSM := $(ROOT)/lib/wolfHSM
WOLFSSL := $(ROOT)/lib/wolfSSL
WOLFPSA := $(ROOT)/lib/wolfPSA

CC ?= cc
BUILD_DIR ?= build
# run builds and runs every WT_SECURE_PSA_PROFILE; run-one takes PROFILE.
PROFILE ?= compat
PROFILES := compat standard lean symmetric

WARN := -std=c11 -O0 -g -Wall -Wextra -Werror -pedantic \
    -Wno-unused-function -Wno-unused-parameter

# The service side: wolfPSA, wolfCrypt and the keyvault over a ramsim NVM,
# built as the crypto partition builds them.
SRV_CFLAGS := \
    -DWOLFSSL_USER_SETTINGS -UHAVE_CONFIG_H \
    -DWOLFHSM_CFG_NO_CRYPTO -DWOLFHSM_CFG_NO_SYS_TIME \
    -DWT_SECURE_PSA=1 -DWT_SECURE_PSA_$(PROFILE)=1 -DWT_MAX_GUESTS=2 -DWT_PSA_GEN_MAX=64U \
    -DWOLFSSL_PSA_ENGINE -DWOLFPSA_CUSTOM_STORE -DWOLFPSA_NO_TRACE -DWOLFPSA_AEAD_BORROW \
    -I. -I$(ROOT)/include -I$(WOLFHSM) -I$(WOLFSSL) -I$(WOLFPSA) \
    -I$(WOLFPSA)/wolfpsa $(EXTRA_CFLAGS)
LIB_CFLAGS := $(SRV_CFLAGS) -O0 -g -w

# The Non-secure side: the client library only, no crypto.
CLI_CFLAGS := -I. -I$(ROOT)/include -I$(WOLFPSA)/wolfpsa $(WARN) \
    -DWT_SECURE_PSA_$(PROFILE)=1 \
    $(EXTRA_CFLAGS)

_SRV_WT := \
    $(ROOT)/src/services/native/psa_crypto_service.c \
    $(ROOT)/src/services/native/native_wire.c \
    $(ROOT)/src/services/native/keyvault.c \
    $(ROOT)/src/services/wolfhsm/wt_hsm_vault.c

_SRV_WH := wh_nvm wh_nvm_flash wh_flash_ramsim wh_flash_unit wh_utils
_SRV_WC := aes coding ecc sp_int wolfmath sha256 random memory error logging \
    hash wc_port misc hmac kdf pwdbased
_SRV_WP := $(notdir $(basename $(filter-out %/psa_store_posix.c \
    %/psa_store_zephyr.c %/psa_attestation.c %/psa_ffm.c %/psa_its.c \
    %/misc_impl.c,$(wildcard $(WOLFPSA)/src/*.c))))

SRV_OBJS := $(addprefix $(BUILD_DIR)/srv_,$(notdir $(_SRV_WT:.c=.o))) \
    $(addprefix $(BUILD_DIR)/wh_,$(addsuffix .o,$(_SRV_WH))) \
    $(addprefix $(BUILD_DIR)/wc_,$(addsuffix .o,$(_SRV_WC))) \
    $(addprefix $(BUILD_DIR)/wp_,$(addsuffix .o,$(_SRV_WP))) \
    $(BUILD_DIR)/server.o

CLI_OBJS := $(BUILD_DIR)/psa_crypto_client.o \
    $(BUILD_DIR)/crypto_native_client.o \
    $(BUILD_DIR)/stub_psa_api_stub.o \
    $(BUILD_DIR)/transport.o

SRV_BIN := $(BUILD_DIR)/psa_server
TEST_BIN := $(BUILD_DIR)/test_psa_secure_crypto

.PHONY: all run run-one compilers sanitize valgrind clean

all: $(SRV_BIN) $(TEST_BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/srv_%.o: $(ROOT)/src/services/native/%.c | $(BUILD_DIR)
	$(CC) $(SRV_CFLAGS) $(WARN) -c -o $@ $<

$(BUILD_DIR)/srv_%.o: $(ROOT)/src/services/wolfhsm/%.c | $(BUILD_DIR)
	$(CC) $(SRV_CFLAGS) $(WARN) -c -o $@ $<

$(BUILD_DIR)/wh_%.o: $(WOLFHSM)/src/%.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wc_%.o: $(WOLFSSL)/wolfcrypt/src/%.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/wp_%.o: $(WOLFPSA)/src/%.c | $(BUILD_DIR)
	$(CC) $(LIB_CFLAGS) -DWT_PSA_POOL_TU -I$(WOLFPSA)/src -c -o $@ $<

$(BUILD_DIR)/server.o: server.c | $(BUILD_DIR)
	$(CC) $(SRV_CFLAGS) -O0 -g -Wall -Wextra -Werror -c -o $@ $<

$(BUILD_DIR)/psa_crypto_client.o: $(ROOT)/src/client/psa_crypto_client.c | $(BUILD_DIR)
	$(CC) $(CLI_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/crypto_native_client.o: $(ROOT)/src/client/crypto_native_client.c | $(BUILD_DIR)
	$(CC) $(CLI_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/stub_psa_api_stub.o: $(WOLFPSA)/src/psa_api_stub.c | $(BUILD_DIR)
	$(CC) -I$(WOLFPSA)/wolfpsa -O0 -g -w -c -o $@ $<

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CLI_CFLAGS) -D_POSIX_C_SOURCE=200809L -c -o $@ $<

$(SRV_BIN): $(SRV_OBJS)
	$(CC) $(EXTRA_LDFLAGS) -o $@ $^

$(TEST_BIN): $(CLI_OBJS) $(BUILD_DIR)/main.o
	$(CC) $(EXTRA_LDFLAGS) -o $@ $^

RUN_ENV = WT_PSA_SERVER=$(abspath $(SRV_BIN)) \
	WT_PSA_FLASH=$(abspath $(BUILD_DIR))/flash.bin

run:
	@for p in $(PROFILES); do \
		echo "== profile $$p"; \
		$(MAKE) --no-print-directory run-one PROFILE=$$p \
			BUILD_DIR=$(BUILD_DIR)/$$p || exit 1; \
	done

run-one: all
	rm -f $(BUILD_DIR)/flash.bin
	$(RUN_ENV) $(TEST_BIN)

compilers:
	$(MAKE) clean run CC=gcc BUILD_DIR=$(BUILD_DIR)/gcc
	$(MAKE) clean run CC=clang BUILD_DIR=$(BUILD_DIR)/clang

sanitize:
	$(MAKE) clean run CC=clang \
		BUILD_DIR=$(BUILD_DIR)/sanitize \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined"

valgrind: all
	rm -f $(BUILD_DIR)/flash.bin
	$(RUN_ENV) valgrind --error-exitcode=1 --leak-check=full \
		--trace-children=yes $(TEST_BIN)

clean:
	rm -rf $(BUILD_DIR)
