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
 * Update authentication tlvs for message passing through (tc). Pass
 * a network byte order message that still contains tlv pointers.
 * Attempt to recalculate icv for each authentication tlv attached.
 * @param cfg  pointer to config that contains sad
 * @param msg  msg that the authentication tlvs should be updated for
 * @return     -1 if sa/key is unknown, otherwise 0
 */
int sad_update_auth_tlv(struct config *cfg,
			struct ptp_message *msg);

/**
 * Append authentication tlv to outbound messages. Includes
 * msg_pre_send() to put message in network byte order so the icv can
 * be calculated.
 * @param cfg     pointer to config that contains sad
 * @param spp     security parameters pointer for desired sa
 * @param key_id  key_id from sa to be used for icv calculation
 * @param msg     msg that the authentication tlv should be attached
 * @return        -1 if sa/key is unknown, otherwise 0
 */
int sad_append_auth_tlv(struct config *cfg, int spp,
			size_t key_id, struct ptp_message *msg);

/**
 * Set the last received sequence id for SYNC/FOLLOW_UP
 * @param cfg    pointer to config that contains sad
 * @param spp    security parameters pointer for desired sa
 * @param seqid  sequence id to store in SA
*/
void sad_set_last_seqid(struct config *cfg,
			int spp, Integer32 seqid);

/**
 * inbound message authentication processing:
 *  1. check seqid (on sync/followup)
 *  2. check for matching ICV
 * @param cfg  pointer to config that contains sad
 * @param spp  security parameters pointer for desired sa
 * @param msg  pointer to formatted message
 * @param raw  pointer to duplicated raw message used for icv compare
 * @return     -EBADMSG if message field expectations are not met
 *             -EPROTO if failed authentication (seqid or icv fail)
 */
int sad_process_auth(struct config *cfg, int spp,
		     struct ptp_message *msg,
		     struct ptp_message *raw);

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

/**
 * Check the everything is ready for security when initializing a port
 * @param spp           security parameters pointer for the port
 * @param active_key_id key_id for outbound messages on the port
 * @param cfg           pointer to config that contains sad
 */
int sad_readiness_check(int spp, size_t active_key_id,
                        struct config *cfg);

#endif
