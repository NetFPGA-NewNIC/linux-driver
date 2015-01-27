################################################################################
#
#  NetFPGA-10G http://www.netfpga.org
#
#  File:
#        Makefile
#
#  Project:
#
#
#  Author:
#        Hwanju Kim
#
#  Description:
#	 This code is initially developed for the Network-as-a-Service (NaaS) project.
#        
#
#  Copyright notice:
#        Copyright (C) 2014 University of Cambridge
#
#  Licence:
#        This file is part of the NetFPGA 10G development base package.
#
#        This file is free code: you can redistribute it and/or modify it under
#        the terms of the GNU Lesser General Public License version 2.1 as
#        published by the Free Software Foundation.
#
#        This package is distributed in the hope that it will be useful, but
#        WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#        Lesser General Public License for more details.
#
#        You should have received a copy of the GNU Lesser General Public
#        License along with the NetFPGA source package.  If not, see
#        http://www.gnu.org/licenses/.
#
#

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
