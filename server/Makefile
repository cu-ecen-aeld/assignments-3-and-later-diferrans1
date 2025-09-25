# Default architecture
ARCH ?= arm64

# Default cross compiler for ARM64
ifeq ($(ARCH),arm64)
CROSS_COMPILE ?= aarch64-none-linux-gnu-
endif

CC := $(CROSS_COMPILE)gcc
CFLAGS += -g -Wall -Werror

all: aesdsocket
default: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f aesdsocket
