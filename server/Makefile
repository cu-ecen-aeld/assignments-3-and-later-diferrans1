CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror
LDFLAGS ?= 
# Add libraries here
LDLIBS ?= -lpthread -lrt

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) $(LDFLAGS) -o aesdsocket aesdsocket.o $(LDLIBS)

aesdsocket.o: aesdsocket.c
	$(CC) $(CFLAGS) -c aesdsocket.c

clean:
	rm -f aesdsocket *.o