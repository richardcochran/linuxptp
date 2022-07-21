#ifndef TEST_H
#define TEST_H

#include "print.h"
#include <string.h>
#include <stdlib.h>

/* sk.c */
#define SK_RECE		1
#define SK_DEBUG	1
#define SK		1

/* raw.c */
#define RAW_RECV	1
#define RAW_SEND	1
#define RAW		1
#define RAW_DEBUG	1

/* port.c */
#define PORT		1

/* transport.c */
#define TRAN_SEND	1

/* ptp4l.c */
#define CONFIG		1
#define TRAN		1

/* msg.c */
#define MSG		1
#if			0
#define DEBUG_POOL
#endif

/* ts2phc_slave.c */
#define SLAVE		1

/* ts2phc_master.c */
#define MASTER		1

/* clock.c */
#define CLOCK		1

/* tsproc.c */
#define TSPROC		1

/* nsm.c */
#define NSM	1

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
