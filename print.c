/**
 * @file print.c
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "print.h"

static int verbose = 0;
static int print_level = LOG_INFO;
static int use_syslog = 1;
static const char *progname;

void print_set_progname(const char *name)
{
	progname = name;
}

void print_set_syslog(int value)
{
	use_syslog = value ? 1 : 0;
}

void print_set_level(int level)
{
	print_level = level;
}

void print_set_verbose(int value)
{
	verbose = value ? 1 : 0;
}

void print(int level, char const *format, ...)
{
	struct timespec ts;
	va_list ap;
	char buf[1024];
	FILE *f;

	if (level > print_level)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	va_start(ap, format);
	vsnprintf(buf, sizeof(buf), format, ap);
	va_end(ap);

	if (verbose) {
		f = level >= LOG_NOTICE ? stdout : stderr;
		fprintf(f, "%s[%ld.%03ld]: %s\n",
			progname ? progname : "",
			ts.tv_sec, ts.tv_nsec / 1000000, buf);
		fflush(f);
	}
	if (use_syslog) {
		syslog(level, "[%ld.%03ld] %s",
		       ts.tv_sec, ts.tv_nsec / 1000000, buf);
	}
}
