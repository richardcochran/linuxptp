/**
 * @file interface.c
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include "interface.h"

void interface_ensure_tslabel(struct interface *iface)
{
	if (!iface->ts_label[0]) {
		strncpy(iface->ts_label, iface->name, MAX_IFNAME_SIZE);
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

void interface_set_name(struct interface *iface, const char *name)
{
	strncpy(iface->name, name, MAX_IFNAME_SIZE);
}
