/**
 * @file ts2phc_nmea_pps_source.c
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "lstab.h"
#include "missing.h"
#include "nmea.h"
#include "print.h"
#include "serial.h"
#include "sock.h"
#include "tmv.h"
#include "ts2phc_nmea_pps_source.h"
#include "ts2phc_pps_source_private.h"
#include "util.h"

#define MAX_RMC_AGE	5000000000ULL
#define NMEA_TMO	2000 /*milliseconds*/

struct ts2phc_nmea_pps_source {
	struct ts2phc_pps_source pps_source;
	struct config *config;
	struct lstab *lstab;
	pthread_t worker;
	/* Protects anonymous struct fields, below, from concurrent access. */
	pthread_mutex_t mutex;
	tmv_t delay_correction;
	struct {
		struct timespec local_monotime;
		struct timespec local_utctime;
		struct timespec rmc_utctime;
		bool rmc_fix_valid;
	};
};

static int open_nmea_connection(const char *host, const char *port,
				const char *serialport, int baud)
{
	int fd;

	if (host[0] && port[0]) {
		fd = sock_open(host, port);
		if (fd == -1) {
			pr_err("failed to open nmea source %s:%s", host, port);
		}
		return fd;
	}
	fd = serial_open(serialport, baud, 0, 0);
	if (fd == -1) {
		pr_err("failed to open nmea source %s", serialport);
	}
	return fd;
}

static void *monitor_nmea_status(void *arg)
{
	struct timespec rxtime, rxtime_rt, tmo = { 2, 0 };
	struct nmea_parser *np = nmea_parser_create();
	struct pollfd pfd = { -1, POLLIN | POLLPRI };
	char *host, input[256], *port, *ptr, *uart;
	struct ts2phc_nmea_pps_source *s = arg;
	int cnt, num, parsed, baud;
	struct nmea_rmc rmc;

	if (!np) {
		pr_err("failed to create NMEA parser");
		return NULL;
	}
	host = config_get_string(s->config, NULL, "ts2phc.nmea_remote_host");
	port = config_get_string(s->config, NULL, "ts2phc.nmea_remote_port");
	uart = config_get_string(s->config, NULL, "ts2phc.nmea_serialport");
	baud = config_get_int(s->config, NULL, "ts2phc.nmea_baudrate");

	while (is_running()) {
		if (pfd.fd == -1) {
			pfd.fd = open_nmea_connection(host, port, uart, baud);
			if (pfd.fd == -1) {
				clock_nanosleep(CLOCK_MONOTONIC, 0, &tmo, NULL);
				continue;
			}
		}
		num = poll(&pfd, 1, NMEA_TMO);
		clock_gettime(CLOCK_MONOTONIC_RAW, &rxtime);
		clock_gettime(CLOCK_REALTIME, &rxtime_rt);
		if (num < 0) {
			pr_err("poll failed");
			break;
		}
		if (!num) {
			pr_err("nmea source timed out");
			close(pfd.fd);
			pfd.fd = -1;
			continue;
		}
		if (pfd.revents & POLLERR) {
			pr_err("nmea source socket error");
			close(pfd.fd);
			pfd.fd = -1;
			continue;
		}
		if (!(pfd.revents & (POLLIN | POLLPRI))) {
			continue;
		}
		cnt = read(pfd.fd, input, sizeof(input));
		if (cnt <= 0) {
			pr_err("failed to read from nmea source");
			close(pfd.fd);
			pfd.fd = -1;
			continue;
		}
		ptr = input;
		do {
			if (!nmea_parse(np, ptr, cnt, &rmc, &parsed)) {
				pthread_mutex_lock(&s->mutex);
				s->local_monotime = rxtime;
				s->local_utctime = rxtime_rt;
				s->rmc_utctime = rmc.ts;
				s->rmc_fix_valid = rmc.fix_valid;
				pthread_mutex_unlock(&s->mutex);
			}
			cnt -= parsed;
			ptr += parsed;
		} while (cnt);
	}

	nmea_parser_destroy(np);
	if (pfd.fd != -1) {
		close(pfd.fd);
	}
	return NULL;
}

static void ts2phc_nmea_pps_source_destroy(struct ts2phc_pps_source *src)
{
	struct ts2phc_nmea_pps_source *s =
		container_of(src, struct ts2phc_nmea_pps_source, pps_source);
	pthread_join(s->worker, NULL);
	pthread_mutex_destroy(&s->mutex);
	lstab_destroy(s->lstab);
	free(s);
}

static int ts2phc_nmea_pps_source_getppstime(struct ts2phc_pps_source *src,
					     struct timespec *ts)
{
	struct ts2phc_nmea_pps_source *m =
		container_of(src, struct ts2phc_nmea_pps_source, pps_source);
	tmv_t delay_t1, delay_t2, duration_since_rmc, local_t1, local_t2, rmc;
	int lstab_error = -1, tai_offset = 0;
	enum lstab_result result;
	struct timespec now;
	int64_t utc_time;
	bool fix_valid;

	clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	local_t2 = timespec_to_tmv(now);

	pthread_mutex_lock(&m->mutex);

	local_t1 = timespec_to_tmv(m->local_monotime);
	delay_t2 = timespec_to_tmv(m->local_utctime);
	rmc = timespec_to_tmv(m->rmc_utctime);
	fix_valid = m->rmc_fix_valid;

	pthread_mutex_unlock(&m->mutex);

	if (!fix_valid) {
		pr_debug("nmea: no valid rmc fix");
		return -1;
	}

	delay_t1 = rmc;
	pr_debug("nmea delay: %" PRId64 " ns",
		 tmv_to_nanoseconds(tmv_sub(delay_t2, delay_t1)));

	duration_since_rmc = tmv_sub(local_t2, local_t1);
	if (tmv_to_nanoseconds(duration_since_rmc) > MAX_RMC_AGE) {
		pr_err("nmea: rmc time stamp stale");
		return -1;
	}

	utc_time = tmv_to_nanoseconds(rmc);
	utc_time /= (int64_t) 1000000000;

	result = lstab_utc2tai(m->lstab, utc_time, &tai_offset);
	switch (result) {
	case LSTAB_OK:
		lstab_error = 0;
		break;
	case LSTAB_UNKNOWN:
		pr_err("nmea: unable to find utc time in leap second table");
		break;
	case LSTAB_EXPIRED:
		pr_err("nmea: utc time is past leap second table expiry date");
		break;
	case LSTAB_AMBIGUOUS:
		pr_err("nmea: utc time stamp is ambiguous");
		break;
	}

	rmc = tmv_add(rmc, duration_since_rmc);
	rmc = tmv_add(rmc, m->delay_correction);
	*ts = tmv_to_timespec(rmc);
	ts->tv_sec += tai_offset;

	return lstab_error;
}

struct ts2phc_pps_source *ts2phc_nmea_pps_source_create(struct ts2phc_private *priv,
							const char *dev)
{
	struct ts2phc_nmea_pps_source *s;
	const char* leapfile;
	int err;

	s = calloc(1, sizeof(*s));
	if (!s) {
		return NULL;
	}
	leapfile = config_get_string(priv->cfg, NULL, "leapfile");
	s->lstab = lstab_create(leapfile);
	if (!s->lstab) {
		free(s);
		return NULL;
	}

	s->pps_source.destroy = ts2phc_nmea_pps_source_destroy;
	s->pps_source.getppstime = ts2phc_nmea_pps_source_getppstime;
	s->config = priv->cfg;
	s->delay_correction = nanoseconds_to_tmv(
			 config_get_int(priv->cfg, NULL, "ts2phc.nmea_delay"));
	pthread_mutex_init(&s->mutex, NULL);
	err = pthread_create(&s->worker, NULL, monitor_nmea_status, s);
	if (err) {
		pr_err("failed to create worker thread: %s", strerror(err));
		lstab_destroy(s->lstab);
		free(s);
		return NULL;
	}

	return &s->pps_source;
}
