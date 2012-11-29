# build circ library
#

# configurable variables
CUTIL_ROOT?=../cutil/src
PREFIX?=/usr/local
COVERAGE?=../coverage
EXTRA_LIBS_ROOT?=/usr/local

SHELL=/bin/sh
NAME=circ
SRC=channel.c commands.c conn.c event_cb.c modes.c msg.c session.c
HDR=channel.h commands.h conn.h event_cb.h modes.h msg.h session.h
OBJ=$(SRC:.c=.o)
OUT=lib$(NAME).a
GCDA=$(SRC:.c=.gcda)
GCNO=$(SRC:.c=.gcno)
GCOV=$(SRC:.c=.c.gcov)
CFLAGS=-O3 -I$(CUTIL_ROOT)/include
debug: CFLAGS=-O0 -gstabs+ -I$(CUTIL_ROOT)/include
coverage: CFLAGS=-fprofile-arcs -ftest-coverage -O0 -gstabs+ -DUNIT_TESTING -I$(CUTIL_ROOT)/include -I../tests
test: CFLAGS=-O0 -gstabs+ -DUNIT_TESTING -I$(CUTIL_ROOT)/include -I../tests
testnr: CFLAGS=-O0 -gstabs+ -DUNIT_TESTING -I$(CUTIL_ROOT)/include -I../tests

# install utility
INSTALL=/usr/bin/install
INSTALL_PROGRAM=$(INSTALL)
INSTALL_DATA=$(INSTALL) -m 644

all: $(OUT) gen_hashes

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)
	rm -rf $(NAME)
	rm -rf include
	rm -rf lib
	ln -s . $(NAME)
	ln -s . include
	ln -s . lib

gen_hashes: gen_hashes.o
	$(CC) $(CFLAGS) -o gen_hashes gen_hashes.o

install: all
	mkdir -p $(PREFIX)/include/$(NAME)
	mkdir -p $(PREFIX)/lib
	$(INSTALL_PROGRAM) --target-directory $(PREFIX)/include/$(NAME)/ *.h
	$(INSTALL_PROGRAM) --target-directory $(PREFIX)/lib/ *.a

uninstall:
	rm -rf $(PREFIX)/include/$(NAME)
	rm -rf $(PREFIX)/lib/$(OUT)

test: all

testnr: all

coverage: all

debug: all

report:
	lcov --base-directory . --directory . -c -o $(NAME).info
	rm -rf $(COVERAGE)
	genhtml -o $(COVERAGE) -t "$(NAME) test coverage" --num-spaces 4 $(NAME).info

clean:
	rm -rf $(NAME)
	rm -rf include
	rm -rf lib
	rm -rf $(OBJ)
	rm -rf $(OUT)
	rm -rf $(GCDA)
	rm -rf $(GCNO)
	rm -rf $(GCOV)
	rm -rf *.info
	rm -rf ev.h.gcov
	rm -rf gen_hashes.gcov
	rm -rf gen_hashes.o
	rm -rf gen_hashes

.PHONY: all install uninstall clean test debug coverage report

