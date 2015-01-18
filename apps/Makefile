PROGRAMS	:= lbuf_tx lbuf_rx lbuf_ping lbuf_gen
INSTALLDIR	:= /usr/local/bin
LDFLAGS		:= -L../lib -llbufnet

ifeq ($(DEBUG),y)
CFLAGS += -g -DDEBUG
endif

CFLAGS += -O2 -Wall -I../include -Wextra -Werror -Wunreachable-code

all: $(PROGRAMS)

.PHONY: clean

lbuf_tx: lbuf_tx.c
	$(CC) $(CFLAGS) -o $@ lbuf_tx.c $(LDFLAGS)
lbuf_rx: lbuf_rx.c
	$(CC) $(CFLAGS) -o $@ lbuf_rx.c $(LDFLAGS)
lbuf_ping: lbuf_ping.c
	$(CC) $(CFLAGS) -o $@ lbuf_ping.c $(LDFLAGS) -lrt
lbuf_gen: lbuf_gen.c
	$(CC) $(CFLAGS) -o $@ lbuf_gen.c $(LDFLAGS)

install: $(PROGRAMS)
	install -m 0755 $(PROGRAMS) $(INSTALLDIR)

clean:
	rm -f $(PROGRAMS)
