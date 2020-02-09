/**
 * @file interface.c
 * @brief Implements network interface data structures.
 * @note Copyright (C) 2020 Richard Cochran <richardcochran@gmail.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include "interface.h"

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
