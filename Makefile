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
#	 This is the makefile for building nf10.ko.
#	 - CONFIG_PROFILE=y enables measurement codes for profiling. lbuf uses
#	 it to measure the time taken for skb alloc/memcpy/protocol processing.
#
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

KERNEL_VER	?= $(shell uname -r)
KERNEL_DIR	?= /lib/modules/$(KERNEL_VER)/build
INSTALL_DIR	?= /lib/modules/$(KERNEL_VER)/extra/nf10/

obj-m += nf10.o
nf10-objs += nf10_main.o
nf10-objs += nf10_lbuf.o
nf10-objs += nf10_ethtool.o
nf10-objs += nf10_user.o

ifeq ($(DEBUG),y)
ccflags-y += -g -DDEBUG
endif

ifeq ($(NAAS),y)
CONFIG_PHY_INIT := y
CONFIG_NO_TIMESTAMP := y
CONFIG_NR_PORTS := 1
endif

ifeq ($(OSNT),y)
ccflags-y += -DCONFIG_OSNT
endif

ifeq ($(CONFIG_PHY_INIT),y)
nf10-objs += ael2005_conf.o
ccflags-y += -DCONFIG_PHY_INIT
endif

ccflags-$(CONFIG_PROFILE) += -DCONFIG_PROFILE
ccflags-$(CONFIG_NO_TIMESTAMP) += -DCONFIG_NO_TIMESTAMP
ifeq ($(CONFIG_NR_PORTS),)
	CONFIG_NR_PORTS := 4
endif
ccflags-y += -DCONFIG_NR_PORTS=$(CONFIG_NR_PORTS)

all: modules lib

.PHONY: modules
modules:
	make -C $(KERNEL_DIR) M=$(PWD) modules

.PHONY: lib
lib:
	make -C lib all

.PHONY: modules_install
modules_install: modules
	install -o root -g root -m 0755 -d $(INSTALL_DIR)
	install -o root -g root -m 0755 nf10.ko $(INSTALL_DIR)
	depmod -a $(KERNEL_VER)

.PHONY: lib_install
lib_install: lib
	make -C lib install

.PHONY: install
install: modules_install lib_install

.PHONY: clean
clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
	make -C lib clean
