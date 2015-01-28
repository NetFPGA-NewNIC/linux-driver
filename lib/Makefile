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

root_dir	:= ../
DRIVER_DIR	:= $(realpath $(root_dir))
INCDIR		:= $(DRIVER_DIR)/include
LIBDIR		:= /usr/local/lib
DRIVER_HEADERS	:= nf10_lbuf_api.h nf10_user.h
LBUFNET_LIB	:= liblbufnet.so
LBUFNET_LIB_VER	:= 0
LBUFNET_OBJ	:= lbufnet.o

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

CFLAGS += -O2 -fPIC -I $(INCDIR) -Wall -Wextra -Werror -Wunreachable-code

all: $(LBUFNET_LIB)

.PHONY: clean install

nf10_lbuf_api.h:
	ln -sf $(DRIVER_DIR)/$@

nf10_user.h:
	ln -sf $(DRIVER_DIR)/$@

lbufnet.o: $(DRIVER_HEADERS)

$(LBUFNET_LIB): $(DRIVER_HEADERS) $(LBUFNET_OBJ)
	$(CC) $(CFLAGS) -shared -o $@ $(LBUFNET_OBJ)

install: $(LBUFNET_LIB)
	install -m 0644 $(LBUFNET_LIB) $(LIBDIR)/$(LBUFNET_LIB).$(LBUFNET_LIB_VER)
	ln -f -s $(LIBDIR)/$(LBUFNET_LIB).$(LBUFNET_LIB_VER) $(LIBDIR)/$(LBUFNET_LIB)
	ldconfig
	cp $(INCDIR)/* /usr/local/include/

clean:
	rm -f $(LBUFNET_LIB) $(LBUFNET_OBJ) $(DRIVER_HEADERS)
