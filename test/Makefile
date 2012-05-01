# build circ test executable
#

# configurable variables
CUTIL_ROOT?=/usr/local

SHELL=/bin/sh
SRC=test_all.c
OBJ=$(SRC:.c=.o)
OUT=test_all
LIBS=-lcirc -lcutil -lcunit -lexpat
CIRC_ROOT=../src
CFLAGS=-O3 -gstabs+ -I$(CIRC_ROOT)/include -I$(CUTIL_ROOT)/include
LDFLAGS=-gstabs+ -L$(CIRC_ROOT)/lib -L$(CUTIL_ROOT)/lib

all:

test: $(OUT)
	./test_all

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

install:

uninstall:

clean:
	rm -rf $(OBJ)
	rm -rf $(OUT)

.PHONY: all install uninstall clean test

