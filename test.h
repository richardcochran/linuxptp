#ifndef TEST_H
#define TEST_H

#include "print.h"
#include <string.h>
#include <stdlib.h>

#define DEBUG_INFO		0
#define FIX_P2P_RESERVED2	1
#define FIX_NS_OVERFLOW		1
#define FIX_CLK_UNLOCK		1
#define REMOVE_TS_SECONDS	1
#define ENLARGE_LOCAL_FREQ_DIFF	1
#define LOCAL_FREQ_DIFF		(10)
#define CLK_LOCK_NUM		(3 * 1e3)
#define FIX_CORRECTION		0

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

/* Values for the messageType field */
#define TEST_SYNC                  0x0
#define TEST_DELAY_REQ             0x1
#define TEST_PDELAY_REQ            0x2
#define TEST_PDELAY_RESP           0x3
#define TEST_FOLLOW_UP             0x8
#define TEST_DELAY_RESP            0x9
#define TEST_PDELAY_RESP_FOLLOW_UP 0xA
#define TEST_ANNOUNCE              0xB
#define TEST_SIGNALING             0xC
#define TEST_MANAGEMENT            0xD
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
			case TEST_SYNC:
				fprintf(stderr, "sync\n");
				break;
			case TEST_FOLLOW_UP:
				fprintf(stderr, "follow_up\n");
				break;
			case TEST_DELAY_REQ:
				fprintf(stderr, "delay_req\n");
				break;
			case TEST_DELAY_RESP:
				fprintf(stderr, "delay_resp\n");
				break;
			case TEST_ANNOUNCE:
				fprintf(stderr, "announce\n");
				break;
			case TEST_PDELAY_REQ:
				fprintf(stderr, "pdelay_req\n");
				break;
			case TEST_PDELAY_RESP:
				fprintf(stderr, "pdelay_resp\n");
				break;
			case TEST_PDELAY_RESP_FOLLOW_UP:
				fprintf(stderr, "pdelay_resp_follow_up\n");
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
