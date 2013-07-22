/**
 * @file pmc_common.h
 * @brief Code shared between PTP management clients.
 * @note Copyright (C) 2013 Miroslav Lichvar <mlichvar@redhat.com>
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

#ifndef HAVE_PMC_COMMON_H
#define HAVE_PMC_COMMON_H

#include "msg.h"

struct pmc;

struct pmc *pmc_create(enum transport_type transport_type, char *iface_name,
		       UInteger8 boundary_hops, UInteger8 domain_number,
		       UInteger8 transport_specific, int zero_datalen);

void pmc_destroy(struct pmc *pmc);

int pmc_get_transport_fd(struct pmc *pmc);

int pmc_send_get_action(struct pmc *pmc, int id);

int pmc_send_set_action(struct pmc *pmc, int id, void *data, int datasize);

struct ptp_message *pmc_recv(struct pmc *pmc);

int pmc_target(struct pmc *pmc, struct PortIdentity *pid);

#endif
