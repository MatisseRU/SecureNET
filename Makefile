CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -std=c11
LDFLAGS ?=

BIN_DIR := build

MAIN_SRC := univ/main.c
MAIN_BIN := $(BIN_DIR)/snet
TEST_BIN := $(BIN_DIR)/test_tcp

EXAMPLE_CRYPTO_SRC := univ/examples/programming_examples.c
EXAMPLE_CRYPTO_BIN := $(BIN_DIR)/example_crypto
EXAMPLE_DEMO_SERVER_SRC := univ/examples/protocol_demo_server.c
EXAMPLE_DEMO_SERVER_BIN := $(BIN_DIR)/protocol_demo_server
EXAMPLE_DEMO_CLIENT_SRC := univ/examples/protocol_demo_client.c
EXAMPLE_DEMO_CLIENT_BIN := $(BIN_DIR)/protocol_demo_client

PLATFORM_LINUX_SRC := platforms/linux/linux.c
PLATFORM_LINUX_OBJ := $(BIN_DIR)/linux_platform.o

ifeq ($(USE_OPENSSL),1)
OPENSSL_CFLAGS := -DSNET_ENABLE_OPENSSL
OPENSSL_LIBS := -lssl -lcrypto
else
OPENSSL_CFLAGS :=
OPENSSL_LIBS :=
endif

.PHONY: all linux windows test examples clean

all: linux

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

linux: $(MAIN_BIN)

$(PLATFORM_LINUX_OBJ): $(PLATFORM_LINUX_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -c $< -o $@

$(MAIN_BIN): $(MAIN_SRC) $(PLATFORM_LINUX_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(MAIN_SRC) $(PLATFORM_LINUX_OBJ) -o $@ $(LDFLAGS) $(OPENSSL_LIBS)

$(TEST_BIN): tests/test_tcp.c $(PLATFORM_LINUX_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) tests/test_tcp.c $(PLATFORM_LINUX_OBJ) -o $@ $(LDFLAGS) $(OPENSSL_LIBS)

$(EXAMPLE_CRYPTO_BIN): $(EXAMPLE_CRYPTO_SRC) $(PLATFORM_LINUX_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(EXAMPLE_CRYPTO_SRC) $(PLATFORM_LINUX_OBJ) -o $@ $(LDFLAGS) $(OPENSSL_LIBS)

$(EXAMPLE_DEMO_SERVER_BIN): $(EXAMPLE_DEMO_SERVER_SRC) $(PLATFORM_LINUX_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(EXAMPLE_DEMO_SERVER_SRC) $(PLATFORM_LINUX_OBJ) -o $@ $(LDFLAGS) $(OPENSSL_LIBS)

$(EXAMPLE_DEMO_CLIENT_BIN): $(EXAMPLE_DEMO_CLIENT_SRC) $(PLATFORM_LINUX_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $(EXAMPLE_DEMO_CLIENT_SRC) $(PLATFORM_LINUX_OBJ) -o $@ $(LDFLAGS) $(OPENSSL_LIBS)

# Base Windows target (cross-compile if mingw is installed)
windows:
	x86_64-w64-mingw32-gcc $(CFLAGS) $(MAIN_SRC) platforms/windows/windows.c -o $(BIN_DIR)/snet.exe

test: $(TEST_BIN)
	$(TEST_BIN)

examples: $(EXAMPLE_CRYPTO_BIN) $(EXAMPLE_DEMO_SERVER_BIN) $(EXAMPLE_DEMO_CLIENT_BIN)

clean:
	rm -rf $(BIN_DIR)
