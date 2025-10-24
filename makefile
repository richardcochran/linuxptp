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

KBUILD_OUTPUT ?=

DEBUG	=
CC	= $(CROSS_COMPILE)gcc
VER     = -DVER=$(version)
CFLAGS	= -Wall $(VER) $(incdefs) $(DEBUG) $(EXTRA_CFLAGS)
LDLIBS	= -lm -lrt -pthread $(EXTRA_LDFLAGS)
PRG	= ptp4l hwstamp_ctl nsm phc2sys phc_ctl pmc timemaster ts2phc tz2alt
SECURITY = sad.o
FILTERS	= filter.o mave.o mmedian.o
SERVOS	= linreg.o ntpshm.o nullf.o pi.o refclock_sock.o servo.o
TRANSP	= raw.o transport.o udp.o udp6.o uds.o
TS2PHC	= ts2phc.o lstab.o nmea.o serial.o sock.o ts2phc_generic_pps_source.o \
 ts2phc_nmea_pps_source.o ts2phc_phc_pps_source.o ts2phc_pps_sink.o ts2phc_pps_source.o
OBJ	= bmc.o clock.o clockadj.o clockcheck.o config.o designated_fsm.o \
 e2e_tc.o fault.o $(FILTERS) fsm.o hash.o interface.o monitor.o msg.o phc.o \
 pmc_common.o port.o port_signaling.o pqueue.o print.o ptp4l.o p2p_tc.o rtnl.o \
 $(SECURITY) $(SERVOS) sk.o stats.o tc.o $(TRANSP) telecom.o tlv.o tsproc.o \
 unicast_client.o unicast_fsm.o unicast_service.o util.o version.o

OBJECTS	= $(OBJ) hwstamp_ctl.o nsm.o phc2sys.o phc_ctl.o pmc.o pmc_agent.o \
 pmc_common.o sysoff.o timemaster.o $(TS2PHC) tz2alt.o
SRC	= $(OBJECTS:.o=.c)
DEPEND	= $(OBJECTS:.o=.d)
srcdir	:= $(dir $(lastword $(MAKEFILE_LIST)))
incdefs := $(shell CC="$(CC)" $(srcdir)/incdefs.sh)
version := $(shell $(srcdir)/version.sh $(srcdir))
VPATH	= $(srcdir)

ifeq (,$(findstring -DUSE_OPENSSL, $(EXTRA_CFLAGS)))
incdefs := $(filter-out -DHAVE_OPENSSL, $(incdefs))
endif

ifneq (,$(findstring -DHAVE_NETTLE, $(incdefs)))
LDLIBS += -lnettle
SECURITY += sad_nettle.o
else ifneq (,$(findstring -DHAVE_GNUTLS, $(incdefs)))
LDLIBS += -lgnutls
SECURITY += sad_gnutls.o
else ifneq (,$(findstring -DHAVE_GNUPG, $(incdefs)))
LDLIBS += -lgcrypt
SECURITY += sad_gnupg.o
else ifneq (,$(findstring -DHAVE_OPENSSL, $(incdefs)))
LDLIBS += -lcrypto
SECURITY += sad_openssl.o
else ifneq (,$(findstring -DHAVE_WOLFCRYPT, $(incdefs)))
LDLIBS += -lwolfssl
SECURITY += sad_wolfcrypt.o
endif

ifneq (,$(findstring -DHAVE_LIBCAP,$(incdefs)))
LDLIBS += -lcap
endif

prefix	= /usr/local
sbindir	= $(prefix)/sbin
mandir	= $(prefix)/man
man8dir	= $(mandir)/man8

all: $(PRG)

ptp4l: $(OBJ)

nsm: config.o $(FILTERS) hash.o interface.o msg.o nsm.o phc.o print.o \
 rtnl.o $(SECURITY) sk.o $(TRANSP) tlv.o tsproc.o util.o version.o

pmc: config.o hash.o interface.o msg.o phc.o pmc.o pmc_common.o print.o \
 $(SECURITY) sk.o tlv.o $(TRANSP) util.o version.o

phc2sys: clockadj.o clockcheck.o config.o hash.o interface.o msg.o \
 phc.o phc2sys.o pmc_agent.o pmc_common.o print.o $(SECURITY) $(SERVOS) \
 sk.o stats.o sysoff.o tlv.o $(TRANSP) util.o version.o

hwstamp_ctl: hwstamp_ctl.o version.o

phc_ctl: phc_ctl.o phc.o sk.o util.o clockadj.o sysoff.o print.o version.o

timemaster: phc.o print.o rtnl.o sk.o timemaster.o util.o version.o

ts2phc: config.o clockadj.o hash.o interface.o msg.o phc.o pmc_agent.o \
 pmc_common.o print.o $(SECURITY) $(SERVOS) sk.o $(TS2PHC) tlv.o transport.o \
 $(TRANSP) util.o version.o

tz2alt: config.o hash.o interface.o lstab.o msg.o phc.o pmc_common.o print.o \
 $(SECURITY) sk.o tlv.o $(TRANSP) tz2alt.o util.o version.o

version.o: .version version.sh $(filter-out version.d,$(DEPEND))

.version: force
	@echo $(version) > .version.new; \
	cmp -s .version .version.new || cp .version.new .version; \
	rm -f .version.new;

force:

install: $(PRG)
	install -p -m 755 -d $(DESTDIR)$(sbindir) $(DESTDIR)$(man8dir)
	install $(PRG) $(DESTDIR)$(sbindir)
	for x in $(PRG:%=%.8); do \
		[ -f $(srcdir)$$x ] && install -p -m 644 -t $(DESTDIR)$(man8dir) $(srcdir)$$x ; \
	done

clean:
	rm -f $(OBJECTS) $(DEPEND) $(PRG)

distclean: clean
	rm -f .version

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

.PHONY: all force clean distclean
