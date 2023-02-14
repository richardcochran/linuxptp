/**
 * @file print.h
 * @brief Logging support functions
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
#ifndef HAVE_PRINT_H
#define HAVE_PRINT_H

#include <syslog.h>

#include "util.h"

#define PRINT_LEVEL_MIN LOG_EMERG
#define PRINT_LEVEL_MAX LOG_DEBUG

#ifdef __GNUC__
__attribute__ ((format (printf, 2, 3)))
#endif
void print(int level, char const *format, ...);

void print_set_progname(const char *name);
void print_set_tag(const char *tag);
void print_set_syslog(int value);
void print_set_level(int level);
void print_set_verbose(int value);

/*
 * Better check print log level before execution of print itself.
 * Otherwise all arguments are evaluated and slow down the system.
 * e.g.   in 'unicast_service.c' unicast_service_clients()
 *                            pid2str() is the killer
 *           pr_debug("%s wants 0x%x", pid2str(&client->portIdentity),
 *                    client->message_types);
 */

extern int print_level;

static inline int print_get_level(void)
{
	return print_level;
}

#define PRINT_CL(l, x...) /* PRINT Check Level */	\
do {							\
	if (print_get_level() >= l)			\
		print(l, x);				\
} while (0)

#define pr_emerg(x...)   PRINT_CL(LOG_EMERG, x)
#define pr_alert(x...)   PRINT_CL(LOG_ALERT, x)
#define pr_crit(x...)    PRINT_CL(LOG_CRIT, x)
#define pr_err(x...)     PRINT_CL(LOG_ERR, x)
#define pr_warning(x...) PRINT_CL(LOG_WARNING, x)
#define pr_notice(x...)  PRINT_CL(LOG_NOTICE, x)
#define pr_info(x...)    PRINT_CL(LOG_INFO, x)
#define pr_debug(x...)   PRINT_CL(LOG_DEBUG, x)

#define PRINT_RL(l, i, x...) \
	do { \
		static time_t last = -i; \
		if (!rate_limited(i, &last)) \
			print(l, x); \
	} while (0);

/* Rate limited versions */
#define pl_emerg(i, x...)   PRINT_RL(LOG_EMERG, i, x)
#define pl_alert(i, x...)   PRINT_RL(LOG_ALERT, i, x)
#define pl_crit(i, x...)    PRINT_RL(LOG_CRIT, i, x)
#define pl_err(i, x...)     PRINT_RL(LOG_ERR, i, x)
#define pl_warning(i, x...) PRINT_RL(LOG_WARNING, i, x)
#define pl_notice(i, x...)  PRINT_RL(LOG_NOTICE, i, x)
#define pl_info(i, x...)    PRINT_RL(LOG_INFO, i, x)
#define pl_debug(i, x...)   PRINT_RL(LOG_DEBUG, i, x)

#endif
