# Define the cross-compilation toolchain prefix (empty by default)
CROSS_COMPILE ?=

# If CROSS_COMPILE is empty, default to gcc; otherwise use $(CROSS_COMPILE)gcc
CC := $(if $(CROSS_COMPILE),$(CROSS_COMPILE)gcc,gcc)

ARCH ?= arm64

# Source files
SRCS = writer.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = writer

# Default target: build the program
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(OBJS)
	$(CROSS_COMPILE)gcc $(OBJS) -o $@

# Rule to compile C source files
%.o: %.c
	$(CROSS_COMPILE)gcc -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(TARGET)