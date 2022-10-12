#ifndef TEST_H
#define TEST_H

#include "print.h"
#include <string.h>
#include <stdlib.h>

#define DEBUG_INFO		0
#define FIX_NS_OVERFLOW		1
#define FIX_CLK_UNLOCK		1
#define REMOVE_TS_SECONDS	1
#define ENLARGE_LOCAL_FREQ_DIFF	1
#define LOCAL_FREQ_DIFF		(10)
#define CLK_LOCK_NUM		(3 * 1e3)

/* sk.c */
#define SK_RECE		DEBUG_INFO
#define SK_DEBUG	DEBUG_INFO
#define SK		DEBUG_INFO

/* raw.c */
#define RAW_RECV	DEBUG_INFO
#define RAW_SEND	DEBUG_INFO
#define RAW		DEBUG_INFO
#define RAW_DEBUG	DEBUG_INFO

/* port.c */
#define PORT		DEBUG_INFO

/* transport.c */
#define TRAN_SEND	DEBUG_INFO

/* ptp4l.c */
#define CONFIG		DEBUG_INFO
#define TRAN		DEBUG_INFO

/* msg.c */
#define MSG		DEBUG_INFO
#if			0
#define DEBUG_POOL
#endif

/* ts2phc_slave.c */
#define SLAVE		DEBUG_INFO

/* ts2phc_master.c */
#define MASTER		DEBUG_INFO

/* clock.c */
#define CLOCK		DEBUG_INFO

/* tsproc.c */
#define TSPROC		DEBUG_INFO

/* nsm.c */
#define NSM		DEBUG_INFO

/* servo.c */
#define SERVO		DEBUG_INFO

/* pi.c */
#define PI		DEBUG_INFO

/* clockadj.c */
#define CLOCKADJ	DEBUG_INFO

/* phc.c */
#define PHC		DEBUG_INFO

#define SYNC_TYPE	0x0
#define FOLLOW_UP_TYPE	0x8
#define DELAY_REQ	0x1
#define DELAY_RESP	0x9
#define PTP_ANNOUNCE	0xb
#define PTP_TYPE_BIT	14
#define PTPV2_BIT1	12
#define PTPV2_BIT2	13
#define PTPV2_TYPE	0x88f7
#define PTPV2_SEQID	44

static inline void get_ptp_type(unsigned char *ptr)
{
	if ((ptr[PTPV2_BIT2] | ptr[PTPV2_BIT1] << 8) == PTPV2_TYPE) {
		fprintf(stderr, "get_ptp_type\n");

		switch (ptr[PTP_TYPE_BIT]) {
			case SYNC_TYPE:
				fprintf(stderr, "sync\n");
				break;
			case FOLLOW_UP_TYPE:
				fprintf(stderr, "follow_up\n");
				break;
			case DELAY_REQ:
				fprintf(stderr, "delay_req\n");
				break;
			case DELAY_RESP:
				fprintf(stderr, "delay_resp\n");
				break;
			case PTP_ANNOUNCE:
				fprintf(stderr, "announce\n");
				break;
			default:
				fprintf(stderr, "other type\n");
				break;
		}
	}
	else
		fprintf(stderr, "Not ptp type\n");
}

static inline int get_ptp_seqid(unsigned char *ptr)
{
	int seqid;

	seqid = (ptr[PTPV2_SEQID + 1] | ptr[PTPV2_SEQID] << 8);
	fprintf(stderr, "seqid: %d\n", seqid);
	return seqid;
}
#endif
