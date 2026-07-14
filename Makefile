CC = gcc
CFLAGS = -Wall -g
TARGETS = hello_exe

.PHONY: all clean test help

all: $(TARGETS)

hello_exe: tests/hello.c
	$(CC) $(CFLAGS) -o hello_exe tests/hello.c

clean:
	rm -f $(TARGETS) *.o
