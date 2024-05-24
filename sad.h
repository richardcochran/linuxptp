/**
 * @file sad.h
 * @brief Security Association Database
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SAD_H
#define HAVE_SAD_H

#include <sys/queue.h>

#include "pdt.h"

struct security_association {
	STAILQ_ENTRY(security_association) list;
	UInteger8  spp;           /* negotiated by key management (see 3.1.68). */
	STAILQ_HEAD(keys_head, security_association_key) keys;
	Boolean    seqnum_ind;    /* not supported in 1588-2019 */
	UInteger16 seqnum_len;    /* value of “S” in Table 131 */
	UInteger16 seqid_window;  /* sequenceID window for anti-replay */
	Boolean    immediate_ind; /* immediate/delayed: always TRUE (for now) */
	Boolean    res_ind;       /* not supported in 1588-2019 */
	UInteger16 res_len;       /* value of “R” in Table 131 */
	Boolean    mutable;       /* allow for mutable correction */
	Integer32  last_seqid;
};

/**
 * Read the defined security association file and append to config.
 * @param cfg  config where security association database should be stored
 * @return     -1 if the read failed, 0 otherwise
 */
int sad_create(struct config *cfg);

/**
 * Free current security association database
 * @param cfg  config where security association database should is stored
 */
void sad_destroy(struct config *cfg);

#endif
