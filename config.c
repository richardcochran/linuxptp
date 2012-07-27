/**
 * @file config.c
 * @note Copyright (C) 2011 Richard Cochran <richardcochran@gmail.com>
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
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "ether.h"

static void scan_line(char *s, struct config *cfg)
{
	double df;
	int i, val;
	Integer8 i8;
	UInteger16 u16;
	UInteger8 u8;
	unsigned char mac[MAC_LEN];

	struct defaultDS *dds = cfg->dds;
	struct port_defaults *pod = cfg->pod;

	if (1 == sscanf(s, " twoStepFlag %d", &val)) {

		if (val) /* TODO - implement one step */
		dds->twoStepFlag = val ? 1 : 0;

	} else if (1 == sscanf(s, " slaveOnly %d", &val)) {

		dds->slaveOnly = val ? 1 : 0;

	} else if (1 == sscanf(s, " priority1 %hhu", &u8)) {

		dds->priority1 = u8;

	} else if (1 == sscanf(s, " priority2 %hhu", &u8)) {

		dds->priority2 = u8;

	} else if (1 == sscanf(s, " domainNumber %hhu", &u8)) {

		if (u8 < 128)
			dds->domainNumber = u8;

	} else if (1 == sscanf(s, " clockClass %hhu", &u8)) {

		dds->clockQuality.clockClass = u8;

	} else if (1 == sscanf(s, " clockAccuracy %hhx", &u8)) {

		dds->clockQuality.clockAccuracy = u8;

	} else if (1 == sscanf(s, " offsetScaledLogVariance %hx", &u16)) {

		dds->clockQuality.offsetScaledLogVariance = u16;

	} else if (1 == sscanf(s, " logAnnounceInterval %hhd", &i8)) {

		pod->logAnnounceInterval = i8;

	} else if (1 == sscanf(s, " logSyncInterval %hhd", &i8)) {

		pod->logSyncInterval = i8;

	} else if (1 == sscanf(s, " logMinDelayReqInterval %hhd", &i8)) {

		pod->logMinDelayReqInterval = i8;

	} else if (1 == sscanf(s, " announceReceiptTimeout %hhu", &u8)) {

		pod->announceReceiptTimeout = u8;

	} else if (1 == sscanf(s, " transportSpecific %hhx", &u8)) {

		pod->transportSpecific = u8 << 4;

	} else if (1 == sscanf(s, " tx_timestamp_retries %u", &val)) {

		if (val > 0)
			*cfg->tx_timestamp_retries = val;

	} else if (1 == sscanf(s, " pi_proportional_const %lf", &df)) {

		if (df > 0.0 && df < 1.0)
			*cfg->pi_proportional_const = df;

	} else if (1 == sscanf(s, " pi_integral_const %lf", &df)) {

		if (df > 0.0 && df < 1.0)
			*cfg->pi_integral_const = df;

	} else if (MAC_LEN == sscanf(s, " ptp_dst_mac %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])) {

		for (i = 0; i < MAC_LEN; i++)
			cfg->ptp_dst_mac[i] = mac[i];

	} else if (MAC_LEN == sscanf(s, " p2p_dst_mac %hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5])) {

		for (i = 0; i < MAC_LEN; i++)
			cfg->p2p_dst_mac[i] = mac[i];
	}
}

int config_read(char *name, struct config *cfg)
{
	FILE *fp;
	char line[1024];

	fp = 0 == strncmp(name, "-", 2) ? stdin : fopen(name, "r");

	if (!fp) {
		perror("fopen");
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		scan_line(line, cfg);
	}

	fclose(fp);
	return 0;
}
