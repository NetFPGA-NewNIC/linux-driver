driver_dir	:= ../
DRIVER_DIR	:= $(realpath $(driver_dir))
DRIVER_HEADERS	:= nf10_lbuf_api.h nf10_user.h
PROGRAMS	:= lbuf_tx lbuf_rx lbuf_ping

ifeq ($(NAAS),y)
	CONFIG_NR_PORTS := 1
	CONFIG_NO_TIMESTAMP := y
endif

ifeq ($(CONFIG_NR_PORTS),)
	CONFIG_NR_PORTS := 4
endif
CFLAGS += -DCONFIG_NR_PORTS=$(CONFIG_NR_PORTS)
ifeq ($(CONFIG_NO_TIMESTAMP),y)
CFLAGS += -DCONFIG_NO_TIMESTAMP
endif

ifeq ($(DEBUG),y)
CFLAGS += -g -DDEBUG
endif

CFLAGS += -O2

all: get_driver_header $(PROGRAMS)

nf10_lbuf_api.h:
	ln -sf $(DRIVER_DIR)/$@

nf10_user.h:
	ln -sf $(DRIVER_DIR)/$@

get_driver_header: $(DRIVER_HEADERS)

lbufnet.o: $(DRIVER_HEADERS)
lbuf_tx.o: $(DRIVER_HEADERS)
lbuf_rx.o: $(DRIVER_HEADERS)
lbuf_ping.o: $(DRIVER_HEADERS)

lbuf_tx: lbuf_tx.o lbufnet.o
lbuf_rx: lbuf_rx.o lbufnet.o
lbuf_ping: lbuf_ping.o lbufnet.o
	$(CC) $(CFLAGS) -o $@ lbuf_ping.o lbufnet.o -lrt

clean:
	rm -f $(PROGRAMS) $(DRIVER_HEADERS) *.o
