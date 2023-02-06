/**
 * @file refclock_sock.c
 * @brief Implements a servo providing samples over Unix domain socket.
 * @note Copyright (C) 2023 Miroslav Lichvar <mlichvar@redhat.com>
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
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "refclock_sock.h"
#include "config.h"
#include "print.h"
#include "servo_private.h"

#define LEAP_NORMAL 0
#define LEAP_INSERT 1
#define LEAP_DELETE 2
#define SOCK_MAGIC 0x534f434b

/* Copied from chrony-3.2/refclock_sock.c */
struct sock_sample {
	/* Time of the measurement (system time) */
	struct timeval tv;

	/* Offset between the true time and the system time (in seconds) */
	double offset;

	/* Non-zero if the sample is from a PPS signal, i.e. another source
	   is needed to obtain seconds */
	int pulse;

	/* 0 - normal, 1 - insert leap second, 2 - delete leap second */
	int leap;

	/* Padding, ignored */
	int _pad;

	/* Protocol identifier (0x534f434b) */
	int magic;
};

struct sock_servo {
	struct servo servo;
	int sock_fd;
	int leap;
};

static void refclock_sock_destroy(struct servo *servo)
{
	struct sock_servo *s = container_of(servo, struct sock_servo, servo);
	free(s);
}

static double refclock_sock_sample(struct servo *servo,
				int64_t offset,
				uint64_t local_ts,
				double weight,
				enum servo_state *state)
{
	struct sock_servo *s = container_of(servo, struct sock_servo, servo);
	struct sock_sample sample;

	memset(&sample, 0, sizeof(sample));
	sample.tv.tv_sec = local_ts / 1000000000ULL;
	sample.tv.tv_usec = local_ts % 1000000000ULL / 1000U;
	sample.offset = -offset / 1e9;
	sample.magic = SOCK_MAGIC;

	switch (s->leap) {
	case -1:
		sample.leap = LEAP_DELETE;
		break;
	case 1:
		sample.leap = LEAP_INSERT;
		break;
	default:
		sample.leap = LEAP_NORMAL;
	}

	if (send(s->sock_fd, &sample, sizeof sample, 0) != sizeof sample) {
		pr_err("refclock_sock: send failed: %m");
		return 0;
	}

	*state = SERVO_UNLOCKED;
	return 0.0;
}

static void refclock_sock_sync_interval(struct servo *servo, double interval)
{
}

static void refclock_sock_reset(struct servo *servo)
{
}

static void refclock_sock_leap(struct servo *servo, int leap)
{
	struct sock_servo *s = container_of(servo, struct sock_servo, servo);

	s->leap = leap;
}

struct servo *refclock_sock_servo_create(struct config *cfg)
{
	char *addr = config_get_string(cfg, NULL, "refclock_sock_address");
	struct sockaddr_un sa;
	struct sock_servo *s;
	int i;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = refclock_sock_destroy;
	s->servo.sample = refclock_sock_sample;
	s->servo.sync_interval = refclock_sock_sync_interval;
	s->servo.reset = refclock_sock_reset;
	s->servo.leap = refclock_sock_leap;

	s->sock_fd = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s->sock_fd < 0) {
		pr_err("refclock_sock: failed to create socket: %m");
		free(s);
		return NULL;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_LOCAL;
	strncpy(sa.sun_path, addr, sizeof(sa.sun_path) - 1);

	/* Wait up to 1 second for the server socket to be created */
	for (i = 10; i >= 0; i--) {
		if (!connect(s->sock_fd, (struct sockaddr *)&sa, sizeof(sa)))
		       break;
		if (i > 0) {
			usleep(100000);
			continue;
		}

		pr_err("refclock_sock: connect failed: %m");
		close(s->sock_fd);
		free(s);
		return NULL;
	}

	return &s->servo;
}
