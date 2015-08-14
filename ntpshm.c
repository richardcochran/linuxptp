/**
 * @file ntpshm.c
 * @brief Implements a servo providing the NTP SHM reference clock to
 *        send the samples to another process.
 * @note Copyright (C) 2014 Miroslav Lichvar <mlichvar@redhat.com>
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
#include <sys/types.h>
#include <sys/shm.h>

#include "config.h"
#include "print.h"
#include "ntpshm.h"
#include "servo_private.h"

/* NTP leap values */
#define LEAP_NORMAL 0x0
#define LEAP_INSERT 0x1
#define LEAP_DELETE 0x2

/* Key of the first SHM segment */
#define SHMKEY 0x4e545030

/* Declaration of the SHM segment from ntp (ntpd/refclock_shm.c) */
struct shmTime {
	int    mode; /* 0 - if valid set
		      *       use values,
		      *       clear valid
		      * 1 - if valid set
		      *       if count before and after read of values is equal,
		      *         use values
		      *       clear valid
		      */
	volatile int count;
	time_t clockTimeStampSec;
	int    clockTimeStampUSec;
	time_t receiveTimeStampSec;
	int    receiveTimeStampUSec;
	int    leap;
	int    precision;
	int    nsamples;
	volatile int valid;
	int    clockTimeStampNSec;
	int    receiveTimeStampNSec;
	int    dummy[8];
};

struct ntpshm_servo {
	struct servo servo;
	struct shmTime *shm;
	int leap;
};

static void ntpshm_destroy(struct servo *servo)
{
	struct ntpshm_servo *s = container_of(servo, struct ntpshm_servo, servo);

	shmdt(s->shm);
	free(s);
}

static double ntpshm_sample(struct servo *servo,
			    int64_t offset,
			    uint64_t local_ts,
			    double weight,
			    enum servo_state *state)
{
	struct ntpshm_servo *s = container_of(servo, struct ntpshm_servo, servo);
	uint64_t clock_ts = local_ts - offset;

	s->shm->mode = 1;
	s->shm->count++;
	s->shm->valid = 0;
	/* TODO: write memory barrier */

	s->shm->clockTimeStampSec = clock_ts / NS_PER_SEC;
	s->shm->clockTimeStampNSec = clock_ts % NS_PER_SEC;
	s->shm->clockTimeStampUSec = s->shm->clockTimeStampNSec / 1000;
	s->shm->receiveTimeStampSec = local_ts / NS_PER_SEC;
	s->shm->receiveTimeStampNSec = local_ts % NS_PER_SEC;
	s->shm->receiveTimeStampUSec = s->shm->receiveTimeStampNSec / 1000;
	s->shm->precision = -30; /* 1 nanosecond */

	switch (s->leap) {
		case -1:
			s->shm->leap = LEAP_DELETE;
			break;
		case 1:
			s->shm->leap = LEAP_INSERT;
			break;
		default:
			s->shm->leap = LEAP_NORMAL;
	}

	/* TODO: write memory barrier */

	s->shm->count++;
	s->shm->valid = 1;

	*state = SERVO_UNLOCKED;
	return 0.0;
}

static void ntpshm_sync_interval(struct servo *servo, double interval)
{
}

static void ntpshm_reset(struct servo *servo)
{
}

static void ntpshm_leap(struct servo *servo, int leap)
{
	struct ntpshm_servo *s = container_of(servo, struct ntpshm_servo, servo);

	s->leap = leap;
}

struct servo *ntpshm_servo_create(struct config *cfg)
{
	struct ntpshm_servo *s;
	int ntpshm_segment = config_get_int(cfg, NULL, "ntpshm_segment");
	int shmid;

	s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->servo.destroy = ntpshm_destroy;
	s->servo.sample = ntpshm_sample;
	s->servo.sync_interval = ntpshm_sync_interval;
	s->servo.reset = ntpshm_reset;
	s->servo.leap = ntpshm_leap;

	shmid = shmget(SHMKEY + ntpshm_segment, sizeof (struct shmTime),
		       IPC_CREAT | 0600);
	if (shmid == -1) {
		pr_err("ntpshm: shmget failed: %m");
		free(s);
		return NULL;
	}

	s->shm = (struct shmTime *)shmat(shmid, 0, 0);
	if (s->shm == (void *)-1) {
		pr_err("ntpshm: shmat failed: %m");
		free(s);
		return NULL;
	}

	return &s->servo;
}
