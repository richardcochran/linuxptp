// SPDX-License-Identifier: GPL-2.0-or-later

#include <stdlib.h>
#include <unistd.h>

#include "contain.h"
#include "dpdk.h"
#include "dpdk_glue.h"
#include "interface.h"
#include "print.h"
#include "transport_private.h"

struct dpdk {
	struct transport t;
	int poll_fd;
};

static int dpdk_close(struct transport *t, struct fdarray *fda)
{
	struct dpdk *dpdk = container_of(t, struct dpdk, t);

	ptp_dpdk_close();
	if (dpdk->poll_fd >= 0) {
		close(dpdk->poll_fd);
		dpdk->poll_fd = -1;
	}
	fda->fd[FD_EVENT] = -1;
	fda->fd[FD_GENERAL] = -1;
	return 0;
}

static int dpdk_open(struct transport *t, struct interface *iface,
		     struct fdarray *fda, enum timestamp_type tt)
{
	struct dpdk *dpdk = container_of(t, struct dpdk, t);
	int poll_fd = -1;

	if (ptp_dpdk_open(interface_name(iface), tt, &poll_fd)) {
		pr_err("dpdk open failed on %s", interface_name(iface));
		return -1;
	}
	if (poll_fd < 0) {
		pr_err("dpdk open returned invalid poll fd");
		ptp_dpdk_close();
		return -1;
	}

	dpdk->poll_fd = poll_fd;
	fda->fd[FD_EVENT] = poll_fd;
	fda->fd[FD_GENERAL] = poll_fd;
	return 0;
}

static int dpdk_recv(struct transport *t, int fd, void *buf, int buflen,
		    struct address *addr, struct hw_timestamp *hwts)
{
	(void) t;
	(void) fd;

	return ptp_dpdk_recv(buf, buflen, addr, hwts);
}

static int dpdk_send(struct transport *t, struct fdarray *fda,
		    enum transport_event event, int peer, void *buf, int buflen,
		    struct address *addr, struct hw_timestamp *hwts)
{
	(void) t;
	(void) fda;

	return ptp_dpdk_send(event, peer, buf, buflen, addr, hwts);
}

static void dpdk_release(struct transport *t)
{
	struct dpdk *dpdk = container_of(t, struct dpdk, t);

	free(dpdk);
}

static int dpdk_physical_addr(struct transport *t, uint8_t *addr)
{
	(void) t;

	return ptp_dpdk_physical_addr(addr);
}

static int dpdk_protocol_addr(struct transport *t, uint8_t *addr)
{
	(void) t;

	return ptp_dpdk_protocol_addr(addr);
}

struct transport *dpdk_transport_create(void)
{
	struct dpdk *dpdk;

	dpdk = calloc(1, sizeof(*dpdk));
	if (!dpdk)
		return NULL;
	dpdk->poll_fd = -1;
	dpdk->t.close = dpdk_close;
	dpdk->t.open = dpdk_open;
	dpdk->t.recv = dpdk_recv;
	dpdk->t.send = dpdk_send;
	dpdk->t.release = dpdk_release;
	dpdk->t.physical_addr = dpdk_physical_addr;
	dpdk->t.protocol_addr = dpdk_protocol_addr;
	return &dpdk->t;
}

