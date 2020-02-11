/**
 * @file interface.c
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <stdlib.h>
#include "interface.h"

struct interface {
	STAILQ_ENTRY(interface) list;
	char name[MAX_IFNAME_SIZE + 1];
	char ts_label[MAX_IFNAME_SIZE + 1];
	struct sk_ts_info ts_info;
};

struct interface *interface_create(const char *name)
{
	struct interface *iface;

	iface = calloc(1, sizeof(struct interface));
	if (!iface) {
		return NULL;
	}
	strncpy(iface->name, name, MAX_IFNAME_SIZE);

	return iface;
}

void interface_destroy(struct interface *iface)
{
	free(iface);
}

void interface_ensure_tslabel(struct interface *iface)
{
	if (!iface->ts_label[0]) {
		memcpy(iface->ts_label, iface->name, MAX_IFNAME_SIZE);
	}
}

int interface_get_tsinfo(struct interface *iface)
{
	return sk_get_ts_info(iface->ts_label, &iface->ts_info);
}

const char *interface_label(struct interface *iface)
{
	return iface->ts_label;
}

const char *interface_name(struct interface *iface)
{
	return iface->name;
}

int interface_phc_index(struct interface *iface)
{
	return iface->ts_info.phc_index;
}

void interface_set_label(struct interface *iface, const char *label)
{
	strncpy(iface->ts_label, label, MAX_IFNAME_SIZE);
}

bool interface_tsinfo_valid(struct interface *iface)
{
	return iface->ts_info.valid ? true : false;
}

bool interface_tsmodes_supported(struct interface *iface, int modes)
{
	if ((iface->ts_info.so_timestamping & modes) == modes) {
		return true;
	}
	return false;
}
