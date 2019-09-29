.POSIX:

CC     := cc
CFLAGS := -std=c89 -O3 -g -pedantic -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE

all: sws
sws: sws.c

clean:
	$(RM) sws
