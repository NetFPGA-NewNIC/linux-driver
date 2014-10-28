driver_dir	:= ../
DRIVER_DIR	:= $(realpath $(driver_dir))
DRIVER_HEADERS	:= nf10_lbuf_api.h nf10_user.h
PROGRAMS	:= lbuf_rx lbuf_tx lbuf_gen

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

CFLAGS += -g

all: get_driver_header $(PROGRAMS)

nf10_lbuf_api.h:
	ln -sf $(DRIVER_DIR)/$@

nf10_user.h:
	ln -sf $(DRIVER_DIR)/$@

get_driver_header: $(DRIVER_HEADERS)

lbuf_rx.o: $(DRIVER_HEADERS)

lbuf_tx.o: $(DRIVER_HEADERS)

lbuf_gen.o: nf10_user.h

clean:
	rm -f $(PROGRAMS) $(DRIVER_HEADERS) *.o
