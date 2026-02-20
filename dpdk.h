/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef HAVE_DPDK_H
#define HAVE_DPDK_H

#include "fd.h"
#include "transport.h"

struct transport *dpdk_transport_create(void);

#endif

