# build circ library
#

# configurable variables
CUTIL_ROOT?=/usr/local
PREFIX?=/usr/local

SHELL=/bin/sh
NAME=circ
SRC=irc_commands.c irc_conn.c irc_modes.c irc_msg.c irc_session.c
HDR=irc_channel.h irc_commands.h irc_conn.h irc_modes.h irc_msg.h irc_session.h
OBJ=$(SRC:.c=.o)
OUT=lib$(NAME).a
CFLAGS=-O0 -gstabs+ -I$(CUTIL_ROOT)/include

# install utility
INSTALL=/usr/bin/install
INSTALL_PROGRAM=$(INSTALL)
INSTALL_DATA=$(INSTALL) -m 644

all: $(OUT) gen_hashes

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)
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

clean:
	rm -rf $(NAME)
	rm -rf include
	rm -rf lib
	rm -rf $(OBJ)
	rm -rf $(OUT)
	rm -rf gen_hashes.o
	rm -rf gen_hashes

.PHONY: all install uninstall clean test

