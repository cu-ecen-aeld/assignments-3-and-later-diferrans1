# Define the cross-compilation toolchain prefix (empty by default)
CROSS_COMPILE ?=

# Compiler: use CROSS_COMPILE prefix if provided, else gcc
CC := $(if $(CROSS_COMPILE),$(CROSS_COMPILE)gcc,gcc)

# Target architecture (default arm64)
ARCH ?= arm64

# Compilation flags
CFLAGS ?= -Wall -Werror
ifeq ($(ARCH),arm64)
    CFLAGS += -march=armv8-a
endif

# Source files
SRCS = writer.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = writer

# Default target
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@

# Rule to compile C source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
