.POSIX:

CC     := cc
CFLAGS := -std=c89 -pedantic -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
PREFIX := /usr/local

all: sws.debug

sws.debug: sws.c
	$(CC) $(CFLAGS) -g -DDEBUG $^ -o $@

sws: sws.c
	$(CC) $(CFLAGS) $^ -o $@

install: sws
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 755 sws $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/sws

clean:
	rm -f sws sws.debug
