.POSIX:

CC     := cc
CFLAGS := -std=c89 -O3 -g -pedantic -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
PREFIX := /usr/local

all: sws
sws: sws.c

install: sws
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp sws $(DESTDIR)$(PREFIX)/bin
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sws

clean:
	rm -f sws
