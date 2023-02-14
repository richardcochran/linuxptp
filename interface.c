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
	struct sk_if_info if_info;
	int vclock;
};

struct interface *interface_create(const char *name)
{
	struct interface *iface;

	iface = calloc(1, sizeof(struct interface));
	if (!iface) {
		return NULL;
	}
	strncpy(iface->name, name, MAX_IFNAME_SIZE);
	strncpy(iface->ts_label, name, MAX_IFNAME_SIZE);
	iface->vclock = -1;

	return iface;
}

void interface_destroy(struct interface *iface)
{
	free(iface);
}

int interface_get_tsinfo(struct interface *iface)
{
	return sk_get_ts_info(iface->ts_label, &iface->ts_info);
}

int interface_get_ifinfo(struct interface *iface)
{
	return sk_get_if_info(iface->ts_label, &iface->if_info);
}

const char *interface_label(struct interface *iface)
{
	return iface->ts_label;
}

bool interface_ifinfo_valid(struct interface *iface)
{
       return iface->if_info.valid ? true : false;
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

void interface_set_vclock(struct interface *iface, int vclock)
{
	iface->vclock = vclock;
}

int interface_get_vclock(struct interface *iface)
{
	return iface->vclock;
}

uint64_t interface_bitperiod(struct interface *iface)
{
	return iface->if_info.iface_bit_period;
}
