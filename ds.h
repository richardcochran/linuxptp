/**
 * @file ds.h
 * @brief Data sets
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
#ifndef HAVE_DS_H
#define HAVE_DS_H

#include "ddt.h"

/* clock data sets */

struct defaultDS {
	Boolean              twoStepFlag;
	Boolean              slaveOnly;
	UInteger16           numberPorts;
	UInteger8            priority1;
	struct ClockQuality  clockQuality;
	UInteger8            priority2;
	struct ClockIdentity clockIdentity;
	UInteger8            domainNumber;
	int                  free_running;
	int                  freq_est_interval; /*log seconds*/
};

struct dataset {
	UInteger8            priority1;
	struct ClockIdentity identity;
	struct ClockQuality  quality;
	UInteger8            priority2;
	UInteger16           stepsRemoved;
	struct PortIdentity  sender;
	struct PortIdentity  receiver;
};

struct currentDS {
	UInteger16   stepsRemoved;
	TimeInterval offsetFromMaster;
	TimeInterval meanPathDelay;
} PACKED;

struct parentDS {
	struct PortIdentity  parentPortIdentity;
	Boolean              parentStats;
	UInteger16           observedParentOffsetScaledLogVariance;
	Integer32            observedParentClockPhaseChangeRate;
	UInteger8            grandmasterPriority1;
	struct ClockQuality  grandmasterClockQuality;
	UInteger8            grandmasterPriority2;
	struct ClockIdentity grandmasterIdentity;
	struct ClockIdentity *ptl;
	unsigned int path_length;
};

#define CURRENT_UTC_OFFSET  35 /* 1 Jul 2012 */
#define INTERNAL_OSCILLATOR 0xA0

struct timePropertiesDS {
	Integer16    currentUtcOffset;
	Boolean      leap61;
	Boolean      leap59;
	Boolean      currentUtcOffsetValid;
	Boolean      ptpTimescale;
	Boolean      timeTraceable;
	Boolean      frequencyTraceable;
	Enumeration8 timeSource;
};

struct port_defaults {
	Integer8 logAnnounceInterval;
	Integer8 logSyncInterval;
	Integer8 logMinDelayReqInterval;
	Integer8 logMinPdelayReqInterval;
	UInteger8 announceReceiptTimeout;
	UInteger8 transportSpecific;
	int path_trace_enabled;
	int follow_up_info;
	int freq_est_interval; /*log seconds*/
};

#endif
