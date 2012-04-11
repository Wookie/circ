# build circ library
#
SHELL=/bin/sh
NAME=circ
SRC=irc_commands.c irc_conn.c irc_modes.c irc_msg.c irc_session.c
HDR=irc_channel.h irc_commands.h irc_conn.h irc_modes.h irc_msg.h irc_session.h
OBJ=$(SRC:.c=.o)
OUT=lib$(NAME).a
CUTIL_ROOT=/usr/local
CFLAGS=-O3 -gstabs+ -I$(CUTIL_ROOT)/include
PREFIX=/usr/local

# install utility
INSTALL=/usr/bin/install
INSTALL_PROGRAM=$(INSTALL)
INSTALL_DATA=$(INSTALL) -m 644

all: $(OUT)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)
	ln -s . $(NAME)
	ln -s . include
	ln -s . lib

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

.PHONY: all install uninstall clean test

