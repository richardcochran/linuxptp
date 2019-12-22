/**
 * @file ts2phc_phc_master.c
 * @note Copyright (C) 2019 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <linux/ptp_clock.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "config.h"
#include "phc.h"
#include "print.h"
#include "missing.h"
#include "ts2phc_master_private.h"
#include "ts2phc_phc_master.h"
#include "util.h"

struct ts2phc_phc_master {
	struct ts2phc_master master;
	clockid_t clkid;
	int channel;
	int fd;
};

static int ts2phc_phc_master_activate(struct config *cfg, const char *dev,
				      struct ts2phc_phc_master *master)
{
	struct ptp_perout_request perout_request;
	struct ptp_pin_desc desc;
	struct timespec ts;

	memset(&desc, 0, sizeof(desc));

	master->channel = config_get_int(cfg, dev, "ts2phc.channel");

	desc.index = config_get_int(cfg, dev, "ts2phc.pin_index");
	desc.func = PTP_PF_PEROUT;
	desc.chan = master->channel;

	if (phc_pin_setfunc(master->clkid, &desc)) {
		pr_warning("Failed to set the pin. Continuing bravely on...");
	}
	if (clock_gettime(master->clkid, &ts)) {
		perror("clock_gettime");
		return -1;
	}
	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = master->channel;
	perout_request.start.sec = ts.tv_sec + 2;
	perout_request.start.nsec = 0;
	perout_request.period.sec = 1;
	perout_request.period.nsec = 0;

	if (ioctl(master->fd, PTP_PEROUT_REQUEST2, &perout_request)) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
		return -1;
	}
	return 0;
}

static void ts2phc_phc_master_destroy(struct ts2phc_master *master)
{
	struct ts2phc_phc_master *m =
		container_of(master, struct ts2phc_phc_master, master);
	struct ptp_perout_request perout_request;

	memset(&perout_request, 0, sizeof(perout_request));
	perout_request.index = m->channel;
	if (ioctl(m->fd, PTP_PEROUT_REQUEST2, &perout_request)) {
		pr_err(PTP_PEROUT_REQUEST_FAILED);
	}
	posix_clock_close(m->clkid);
	free(m);
}

static int ts2phc_phc_master_getppstime(struct ts2phc_master *m,
					struct timespec *ts)
{
	struct ts2phc_phc_master *master =
		container_of(m, struct ts2phc_phc_master, master);
	return clock_gettime(master->clkid, ts);
}

struct ts2phc_master *ts2phc_phc_master_create(struct config *cfg,
					       const char *dev)
{
	struct ts2phc_phc_master *master;
	int junk;

	master = calloc(1, sizeof(*master));
	if (!master) {
		return NULL;
	}
	master->master.destroy = ts2phc_phc_master_destroy;
	master->master.getppstime = ts2phc_phc_master_getppstime;

	master->clkid = posix_clock_open(dev, &junk);
	if (master->clkid == CLOCK_INVALID) {
		free(master);
		return NULL;
	}
	master->fd = CLOCKID_TO_FD(master->clkid);

	pr_debug("PHC master %s has ptp index %d", dev, junk);

	if (ts2phc_phc_master_activate(cfg, dev, master)) {
		ts2phc_phc_master_destroy(&master->master);
		return NULL;
	}

	return &master->master;
}
