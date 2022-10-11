/**
 * @file missing.h
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

/*
 * When glibc offers the syscall, this will go away.
 */
#ifndef HAVE_MISSING_H
#define HAVE_MISSING_H

#include <linux/ptp_clock.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#ifndef ADJ_TAI
#define ADJ_TAI 0x0080
#endif

#ifndef ADJ_NANO
#define ADJ_NANO 0x2000
#endif

#ifndef ADJ_SETOFFSET
#define ADJ_SETOFFSET 0x0100
#endif

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

#ifndef ETH_P_PRP
/* ETH_P_PRP is defined in if_ether.h from kernel 3.13 */
#define ETH_P_PRP   0x88FB   /* IEC 62439-3 PRP/HSRv0  */
#endif

#ifndef HAVE_ONESTEP_SYNC
enum _missing_hwtstamp_tx_types {
	HWTSTAMP_TX_ONESTEP_SYNC = 2,
};
#endif

#ifndef HAVE_ONESTEP_P2P
enum {
	HWTSTAMP_TX_ONESTEP_P2P = 3,
};
#endif

#ifndef HAVE_VCLOCKS
enum {
	SOF_TIMESTAMPING_BIND_PHC = (1 << 15),
};

struct so_timestamping {
	int flags;
	int bind_phc;
};
#endif

#ifndef HWTSTAMP_FLAG_BONDED_PHC_INDEX
enum {
	HWTSTAMP_FLAG_BONDED_PHC_INDEX = (1<<0),
};
#endif

#ifdef PTP_EXTTS_REQUEST2
#define PTP_EXTTS_REQUEST_FAILED "PTP_EXTTS_REQUEST2 failed: %m"
#else
#define PTP_EXTTS_REQUEST_FAILED "PTP_EXTTS_REQUEST failed: %m"
#define PTP_EXTTS_REQUEST2 PTP_EXTTS_REQUEST
#endif

#ifdef PTP_PEROUT_REQUEST2
#define PTP_PEROUT_REQUEST_FAILED "PTP_PEROUT_REQUEST2 failed: %m"
#else
#define PTP_PEROUT_REQUEST_FAILED "PTP_PEROUT_REQUEST failed: %m"
#define PTP_PEROUT_REQUEST2 PTP_PEROUT_REQUEST
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)

/* from upcoming Linux kernel version 5.8 */
struct compat_ptp_clock_caps {
	int max_adj;   /* Maximum frequency adjustment in parts per billon. */
	int n_alarm;   /* Number of programmable alarms. */
	int n_ext_ts;  /* Number of external time stamp channels. */
	int n_per_out; /* Number of programmable periodic signals. */
	int pps;       /* Whether the clock supports a PPS callback. */
	int n_pins;    /* Number of input/output pins. */
	/* Whether the clock supports precise system-device cross timestamps */
	int cross_timestamping;
	/* Whether the clock supports adjust phase */
	int adjust_phase;
	int rsv[12];   /* Reserved for future use. */
};

#define ptp_clock_caps compat_ptp_clock_caps

#endif /*LINUX_VERSION_CODE < 5.8*/

/*
 * Bits of the ptp_perout_request.flags field:
 */

#ifndef PTP_PEROUT_ONE_SHOT
#define PTP_PEROUT_ONE_SHOT		(1<<0)
#endif

#ifndef PTP_PEROUT_DUTY_CYCLE
#define PTP_PEROUT_DUTY_CYCLE		(1<<1)
#endif

#ifndef PTP_PEROUT_PHASE
#define PTP_PEROUT_PHASE		(1<<2)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)

struct compat_ptp_perout_request {
	union {
		/*
		 * Absolute start time.
		 * Valid only if (flags & PTP_PEROUT_PHASE) is unset.
		 */
		struct ptp_clock_time start;
		/*
		 * Phase offset. The signal should start toggling at an
		 * unspecified integer multiple of the period, plus this value.
		 * The start time should be "as soon as possible".
		 * Valid only if (flags & PTP_PEROUT_PHASE) is set.
		 */
		struct ptp_clock_time phase;
	};
	struct ptp_clock_time period; /* Desired period, zero means disable. */
	unsigned int index;           /* Which channel to configure. */
	unsigned int flags;
	union {
		/*
		 * The "on" time of the signal.
		 * Must be lower than the period.
		 * Valid only if (flags & PTP_PEROUT_DUTY_CYCLE) is set.
		 */
		struct ptp_clock_time on;
		/* Reserved for future use. */
		unsigned int rsv[4];
	};
};

#define ptp_perout_request compat_ptp_perout_request

#endif /* LINUX_VERSION_CODE < 5.9 */

#ifndef PTP_MAX_SAMPLES
#define PTP_MAX_SAMPLES 25 /* Maximum allowed offset measurement samples. */
#endif /* PTP_MAX_SAMPLES */

#ifndef PTP_SYS_OFFSET

#define PTP_SYS_OFFSET     _IOW(PTP_CLK_MAGIC, 5, struct ptp_sys_offset)

struct ptp_sys_offset {
	unsigned int n_samples; /* Desired number of measurements. */
	unsigned int rsv[3];    /* Reserved for future use. */
	/*
	 * Array of interleaved system/phc time stamps. The kernel
	 * will provide 2*n_samples + 1 time stamps, with the last
	 * one as a system time stamp.
	 */
	struct ptp_clock_time ts[2 * PTP_MAX_SAMPLES + 1];
};

#endif /* PTP_SYS_OFFSET */

#ifndef PTP_SYS_OFFSET_PRECISE

#define PTP_SYS_OFFSET_PRECISE \
	_IOWR(PTP_CLK_MAGIC, 8, struct ptp_sys_offset_precise)

struct ptp_sys_offset_precise {
	struct ptp_clock_time device;
	struct ptp_clock_time sys_realtime;
	struct ptp_clock_time sys_monoraw;
	unsigned int rsv[4];    /* Reserved for future use. */
};

#endif /* PTP_SYS_OFFSET_PRECISE */

#ifndef PTP_SYS_OFFSET_EXTENDED

#define PTP_SYS_OFFSET_EXTENDED \
	_IOWR(PTP_CLK_MAGIC, 9, struct ptp_sys_offset_extended)

struct ptp_sys_offset_extended {
	unsigned int n_samples; /* Desired number of measurements. */
	unsigned int rsv[3];    /* Reserved for future use. */
	/*
	 * Array of [system, phc, system] time stamps. The kernel will provide
	 * 3*n_samples time stamps.
	 */
	struct ptp_clock_time ts[PTP_MAX_SAMPLES][3];
};

#endif /* PTP_SYS_OFFSET_EXTENDED */

#ifndef PTP_PIN_SETFUNC

enum ptp_pin_function {
	PTP_PF_NONE,
	PTP_PF_EXTTS,
	PTP_PF_PEROUT,
	PTP_PF_PHYSYNC,
};

struct ptp_pin_desc {
	char name[64];
	unsigned int index;
	unsigned int func;
	unsigned int chan;
	unsigned int rsv[5];
};

#define PTP_PIN_SETFUNC    _IOW(PTP_CLK_MAGIC, 7, struct ptp_pin_desc)

#endif /*!PTP_PIN_SETFUNC*/

#ifdef PTP_PIN_SETFUNC2
#define PTP_PIN_SETFUNC_FAILED "PTP_PIN_SETFUNC2 failed: %m"
#else
#define PTP_PIN_SETFUNC_FAILED "PTP_PIN_SETFUNC failed: %m"
#define PTP_PIN_SETFUNC2 PTP_PIN_SETFUNC
#endif

#ifndef LIST_FOREACH_SAFE
#define	LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = LIST_FIRST((head));				\
	    (var) && ((tvar) = LIST_NEXT((var), field), 1);		\
	    (var) = (tvar))
#endif

#ifndef SIOCGHWTSTAMP
#define SIOCGHWTSTAMP 0x89b1
#endif

#ifndef SO_SELECT_ERR_QUEUE
#define SO_SELECT_ERR_QUEUE 45
#endif

#ifndef HAVE_CLOCK_ADJTIME
static inline int clock_adjtime(clockid_t id, struct timex *tx)
{
	return syscall(__NR_clock_adjtime, id, tx);
}
#endif

#ifndef IFLA_BOND_MAX
enum {
	IFLA_BOND_UNSPEC,
	IFLA_BOND_MODE,
	IFLA_BOND_ACTIVE_SLAVE,
	IFLA_BOND_MIIMON,
	IFLA_BOND_UPDELAY,
	IFLA_BOND_DOWNDELAY,
	IFLA_BOND_USE_CARRIER,
	IFLA_BOND_ARP_INTERVAL,
	IFLA_BOND_ARP_IP_TARGET,
	IFLA_BOND_ARP_VALIDATE,
	IFLA_BOND_ARP_ALL_TARGETS,
	IFLA_BOND_PRIMARY,
	IFLA_BOND_PRIMARY_RESELECT,
	IFLA_BOND_FAIL_OVER_MAC,
	IFLA_BOND_XMIT_HASH_POLICY,
	IFLA_BOND_RESEND_IGMP,
	IFLA_BOND_NUM_PEER_NOTIF,
	IFLA_BOND_ALL_SLAVES_ACTIVE,
	IFLA_BOND_MIN_LINKS,
	IFLA_BOND_LP_INTERVAL,
	IFLA_BOND_PACKETS_PER_SLAVE,
	IFLA_BOND_AD_LACP_RATE,
	IFLA_BOND_AD_SELECT,
	IFLA_BOND_AD_INFO,
	IFLA_BOND_AD_ACTOR_SYS_PRIO,
	IFLA_BOND_AD_USER_PORT_KEY,
	IFLA_BOND_AD_ACTOR_SYSTEM,
	IFLA_BOND_TLB_DYNAMIC_LB,
	__IFLA_BOND_MAX,
};

#define IFLA_BOND_MAX   (__IFLA_BOND_MAX - 1)
#endif	/*IFLA_BOND_MAX*/

#ifndef NLA_TYPE_MAX
enum {
        NLA_UNSPEC,
        NLA_U8,
        NLA_U16,
        NLA_U32,
        NLA_U64,
        NLA_STRING,
        NLA_FLAG,
        NLA_MSECS,
        NLA_NESTED,
        __NLA_TYPE_MAX,
};
#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)
#endif /*NLA_TYPE_MAX*/

#ifndef ETHTOOL_GENL_NAME
#define ETHTOOL_GENL_NAME "ethtool"
#define ETHTOOL_GENL_VERSION 1
#endif

#ifndef HAVE_VCLOCKS
enum {
	ETHTOOL_MSG_USER_NONE,
	ETHTOOL_MSG_STRSET_GET,
	ETHTOOL_MSG_LINKINFO_GET,
	ETHTOOL_MSG_LINKINFO_SET,
	ETHTOOL_MSG_LINKMODES_GET,
	ETHTOOL_MSG_LINKMODES_SET,
	ETHTOOL_MSG_LINKSTATE_GET,
	ETHTOOL_MSG_DEBUG_GET,
	ETHTOOL_MSG_DEBUG_SET,
	ETHTOOL_MSG_WOL_GET,
	ETHTOOL_MSG_WOL_SET,
	ETHTOOL_MSG_FEATURES_GET,
	ETHTOOL_MSG_FEATURES_SET,
	ETHTOOL_MSG_PRIVFLAGS_GET,
	ETHTOOL_MSG_PRIVFLAGS_SET,
	ETHTOOL_MSG_RINGS_GET,
	ETHTOOL_MSG_RINGS_SET,
	ETHTOOL_MSG_CHANNELS_GET,
	ETHTOOL_MSG_CHANNELS_SET,
	ETHTOOL_MSG_COALESCE_GET,
	ETHTOOL_MSG_COALESCE_SET,
	ETHTOOL_MSG_PAUSE_GET,
	ETHTOOL_MSG_PAUSE_SET,
	ETHTOOL_MSG_EEE_GET,
	ETHTOOL_MSG_EEE_SET,
	ETHTOOL_MSG_TSINFO_GET,
	ETHTOOL_MSG_CABLE_TEST_ACT,
	ETHTOOL_MSG_CABLE_TEST_TDR_ACT,
	ETHTOOL_MSG_TUNNEL_INFO_GET,
	ETHTOOL_MSG_FEC_GET,
	ETHTOOL_MSG_FEC_SET,
	ETHTOOL_MSG_MODULE_EEPROM_GET,
	ETHTOOL_MSG_STATS_GET,
	ETHTOOL_MSG_PHC_VCLOCKS_GET,
};

enum {
	ETHTOOL_MSG_KERNEL_NONE,
	ETHTOOL_MSG_STRSET_GET_REPLY,
	ETHTOOL_MSG_LINKINFO_GET_REPLY,
	ETHTOOL_MSG_LINKINFO_NTF,
	ETHTOOL_MSG_LINKMODES_GET_REPLY,
	ETHTOOL_MSG_LINKMODES_NTF,
	ETHTOOL_MSG_LINKSTATE_GET_REPLY,
	ETHTOOL_MSG_DEBUG_GET_REPLY,
	ETHTOOL_MSG_DEBUG_NTF,
	ETHTOOL_MSG_WOL_GET_REPLY,
	ETHTOOL_MSG_WOL_NTF,
	ETHTOOL_MSG_FEATURES_GET_REPLY,
	ETHTOOL_MSG_FEATURES_SET_REPLY,
	ETHTOOL_MSG_FEATURES_NTF,
	ETHTOOL_MSG_PRIVFLAGS_GET_REPLY,
	ETHTOOL_MSG_PRIVFLAGS_NTF,
	ETHTOOL_MSG_RINGS_GET_REPLY,
	ETHTOOL_MSG_RINGS_NTF,
	ETHTOOL_MSG_CHANNELS_GET_REPLY,
	ETHTOOL_MSG_CHANNELS_NTF,
	ETHTOOL_MSG_COALESCE_GET_REPLY,
	ETHTOOL_MSG_COALESCE_NTF,
	ETHTOOL_MSG_PAUSE_GET_REPLY,
	ETHTOOL_MSG_PAUSE_NTF,
	ETHTOOL_MSG_EEE_GET_REPLY,
	ETHTOOL_MSG_EEE_NTF,
	ETHTOOL_MSG_TSINFO_GET_REPLY,
	ETHTOOL_MSG_CABLE_TEST_NTF,
	ETHTOOL_MSG_CABLE_TEST_TDR_NTF,
	ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY,
	ETHTOOL_MSG_FEC_GET_REPLY,
	ETHTOOL_MSG_FEC_NTF,
	ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY,
	ETHTOOL_MSG_STATS_GET_REPLY,
	ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY,
};

enum {
	ETHTOOL_A_HEADER_UNSPEC,
	ETHTOOL_A_HEADER_DEV_INDEX,		/* u32 */
	ETHTOOL_A_HEADER_DEV_NAME,		/* string */
	ETHTOOL_A_HEADER_FLAGS,			/* u32 - ETHTOOL_FLAG_* */
	__ETHTOOL_A_HEADER_CNT,
	ETHTOOL_A_HEADER_MAX = __ETHTOOL_A_HEADER_CNT - 1
};

enum {
	ETHTOOL_A_PHC_VCLOCKS_UNSPEC,
	ETHTOOL_A_PHC_VCLOCKS_HEADER,			/* nest - _A_HEADER_* */
	ETHTOOL_A_PHC_VCLOCKS_NUM,			/* u32 */
	ETHTOOL_A_PHC_VCLOCKS_INDEX,			/* array, s32 */
	__ETHTOOL_A_PHC_VCLOCKS_CNT,
	ETHTOOL_A_PHC_VCLOCKS_MAX = (__ETHTOOL_A_PHC_VCLOCKS_CNT - 1)
};

#endif /* HAVE_VCLOCKS */

#ifdef __UCLIBC__

#if (_XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L) && \
	defined __UCLIBC_HAS_THREADS_NATIVE__

#include <sys/timerfd.h>

#else

#define TFD_TIMER_ABSTIME (1 << 0)

/*
 * clock_nanosleep is supported in uclic-ng since v1.0.31 even without threads.
 */
#if defined __USE_XOPEN2K && defined __UCLIBC_HAS_ADVANCED_REALTIME__

#include <sys/time.h>

#else

static inline int clock_nanosleep(clockid_t clock_id, int flags,
				  const struct timespec *request,
				  struct timespec *remain)
{
	return syscall(__NR_clock_nanosleep, clock_id, flags, request, remain);
}

#endif

static inline int timerfd_create(int clockid, int flags)
{
	return syscall(__NR_timerfd_create, clockid, flags);
}

static inline int timerfd_settime(int fd, int flags,
				  const struct itimerspec *new_value,
				  struct itimerspec *old_value)
{
	return syscall(__NR_timerfd_settime, fd, flags, new_value, old_value);
}
#endif

#else /*__UCLIBC__*/

#include <sys/timerfd.h>

#endif

#endif
