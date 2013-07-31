# build circ test executable
#

# configurable variables
CUTIL_ROOT?=../cutil/src
EXTRA_LIBS_ROOT?=/usr/local

SHELL=/bin/sh
SRC=test_all.c test_flags.c test_msg.c ../cutil/tests/test_flags.c
OBJ=$(SRC:.c=.o)
GCDA=$(SRC:.c=.gcda)
GCNO=$(SRC:.c=.gcno)
GCOV=$(SRC:.c=.c.gcov)
OUT=test_all
LIBS=-lcirc -lcutil -lcunit -lev -lm
CIRC_ROOT=../src
CFLAGS=-O0 -gstabs+ -I$(CIRC_ROOT)/include -I$(CUTIL_ROOT)/include
LDFLAGS=-gstabs+ -L$(CIRC_ROOT)/lib -L$(CUTIL_ROOT)/lib
# set LDFLAGS to something gcov can use
coverage: LDFLAGS=-fprofile-arcs -O0 -gstabs+ -L$(CIRC_ROOT)/lib -L$(CUTIL_ROOT)/lib -L$(EXTRA_LIBS_ROOT)/lib

all:

test: $(OUT)
	./test_all

testnr: $(OUT)

coverage: $(OUT)
	./test_all

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

install:

uninstall:

report:

clean:
	rm -rf $(OBJ)
	rm -rf $(OUT)
	rm -rf $(GCDA)
	rm -rf $(GCNO)
	rm -rf $(GCOV)

.PHONY: all install uninstall clean test coverage report

