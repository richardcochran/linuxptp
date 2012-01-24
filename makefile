#
# Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

KBUILD_OUTPUT ?= /lib/modules/$(shell uname -r)/build

DEBUG	=
CC	= gcc
INC	= -I$(KBUILD_OUTPUT)/usr/include
CFLAGS	= -Wall $(INC) $(DEBUG)
LDFLAGS	=
LDLIBS	= -lm -lrt
PRG	= ptp4l phc2sys
OBJ	= bmc.o clock.o config.o fsm.o ptp4l.o mave.o msg.o phc.o pi.o port.o \
 print.o servo.o tmtab.o transport.o udp.o util.o

OBJECTS	= $(OBJ) phc2sys.o
SRC	= $(OBJECTS:.o=.c)
DEPEND	= $(OBJECTS:.o=.d)
srcdir	:= $(dir $(lastword $(MAKEFILE_LIST)))
VPATH	= $(srcdir)

all: ptp4l phc2sys

ptp4l: $(OBJ)

phc2sys: phc2sys.o

clean:
	rm -f $(OBJECTS) $(DEPEND)

distclean: clean
	rm -f $(PRG)

# Implicit rule to generate a C source file's dependencies.
%.d: %.c
	@echo DEPEND $<; \
	rm -f $@; \
	$(CC) -MM $(CPPFLAGS) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), distclean)
-include $(DEPEND)
endif
endif
