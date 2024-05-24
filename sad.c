/**
 * @file sad.c
 * @brief Security Association Database
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

#include "config.h"
#include "msg.h"
#include "print.h"
#include "sad.h"
#include "sad_private.h"
#include "tlv.h"

static struct security_association *current_sa;
static struct integrity_alg_info supported_algorithms [] = {
	{ "SHA256-128", HMAC_SHA256_128, 0,  16 },
	{ "SHA256",     HMAC_SHA256,     0,  32 },
	{ "AES128",     CMAC_AES128,     16, 16 },
	{ "AES256",     CMAC_AES256,     32, 16 },
	{ NULL, 0, 0, 0 },
};

/* spp should be in the range [0 - 255] */
static inline struct security_association *sad_get_association(struct config *cfg,
								int spp)
{
	struct security_association *sa;
	STAILQ_FOREACH(sa, &cfg->security_association_database, list) {
		if (sa->spp == spp) {
			return sa;
		}
	}

	pr_debug("sa %u not present", spp);
	return NULL;
}

/* key_id should be in the range [1 - 2^32-1] */
static inline struct security_association_key *sad_get_key(struct security_association *sa,
							   size_t key_id)
{
	struct security_association_key *key;
	if (key_id < 1 || key_id > UINT32_MAX) {
		return NULL;
	}

	STAILQ_FOREACH(key, &sa->keys, list) {
		if (key->key_id == key_id) {
			return key;
		}
	}

	pr_debug("sa %u: key %zu not present", sa->spp, key_id);
	return NULL;
}

static inline size_t sad_get_auth_tlv_len(struct security_association *sa,
					  size_t icv_len)
{
	return sizeof(struct authentication_tlv) + /* size of base tlv */
	       (sa->res_ind ? sa->res_len : 0) + /* size of res field */
	       (sa->seqnum_ind ? sa->seqnum_len : 0) + /* size of seqnum field */
	       icv_len; /* size of icv (defined by key) */
}

/**
 * generate and append icv to an outbound message.
 * when mutable is set, set correction to zero before hash and
 * replace when done.
 */
static int sad_generate_icv(struct security_association *sa,
			    struct security_association_key *key,
			    struct ptp_message *msg, void *icv)
{
	size_t data_len, icv_len = 0;
	Integer64 correction = 0;

	/* msg length to start of icv */
	data_len = (char *) icv - (char *) msg;

	/* set correction to zero if mutable fields are allowed */
	if (sa->mutable && msg->header.correction != 0) {
		correction = msg->header.correction;
		msg->header.correction = 0;
	}

	/* generate digest */
	icv_len = sad_hash(key->data, msg, data_len,
			   icv, key->icv->digest_len);

	if (correction != 0) {
		msg->header.correction = correction;
	}

	return icv_len;
}

int sad_update_auth_tlv(struct config *cfg,
			struct ptp_message *msg)
{
	struct tlv_extra *extra;
	struct authentication_tlv *auth;
	struct security_association *sa;
	struct security_association_key *key;
	void *sequenceNo, *res, *icv;
	/* update any/all authentication tlvs now */
	TAILQ_FOREACH(extra, &msg->tlv_list, list) {
		if (ntohs(extra->tlv->type) != TLV_AUTHENTICATION) {
			continue;
		}
		auth = (struct authentication_tlv *) extra->tlv;
		/* retrieve sa specified by spp in tlv */
		sa = sad_get_association(cfg, auth->spp);
		if (!sa) {
			return -1;
		}
		/* verify res, seqnum, disclosedKey field indicators match expectations */
		if ((sa->res_ind != ((auth->secParamIndicator & 0x1) != 0)) ||
		    (sa->seqnum_ind != ((auth->secParamIndicator & 0x2) != 0)) ||
		    (sa->immediate_ind == ((auth->secParamIndicator & 0x4) != 0))) {
			pr_debug("sa %u: unable to update auth tlv,"
				 " sec param %d does not match",
				 sa->spp, auth->secParamIndicator);
			return -1;
		}
		/* retrieve key specified by keyid in tlv */
		key = sad_get_key(sa, ntohl(auth->keyID));
		if (!key) {
			pr_debug("sa %u: unable to update auth tlv,"
				 " unable to retrieve key %u",
				 sa->spp, ntohl(auth->keyID));
			return -1;
		}
		/* confirm tlv length to be generated matches what already exists */
		if (ntohs(auth->length) != sad_get_auth_tlv_len(sa, key->icv->digest_len) - 4) {
			pr_debug("sa %u: unable to update auth tlv,"
				 " length is not maintained", sa->spp);
			return -1;
		}
		/* set pointers to extra data used for icv generation */
		sequenceNo = auth->data;
		res = sequenceNo + (sa->seqnum_ind ? sa->seqnum_len : 0);
		icv = res + (sa->res_ind ? sa->res_len : 0);
		if (!sad_generate_icv(sa, key, msg, icv)) {
			return -1;
		}
	}

	return 0;
}

/**
 * append auth tlv to outbound messages. This includes:
 * 1. retrieve security association, key
 * 2. append tlv aind fill in all values besides icv
 * 3. run msg_pre_send to format message to send on wire
 * 4. generate icv and attach to message
 */
int sad_append_auth_tlv(struct config *cfg, int spp,
			size_t key_id, struct ptp_message *msg)
{
	struct tlv_extra *extra;
	struct authentication_tlv *auth;
	struct security_association *sa;
	struct security_association_key *key;
	void *sequenceNo, *res, *icv;
	/* immediately return if security is not configured */
	if (spp < 0 || key_id < 1) {
		return -1;
	}
	/* retrieve sa specified by spp */
	sa = sad_get_association(cfg, spp);
	if (!sa) {
		return -1;
	}
	/* retrieve key specified by key_id */
	key = sad_get_key(sa, key_id);
	if (!key) {
		return -1;
	}
	/* populate tlv fields */
	extra = msg_tlv_append(msg, sad_get_auth_tlv_len(sa, key->icv->digest_len));
	if (!extra) {
		return -1;
	}
	auth = (struct authentication_tlv *) extra->tlv;
	auth->type = TLV_AUTHENTICATION;
	auth->length = sad_get_auth_tlv_len(sa, key->icv->digest_len) - 4;
	auth->spp = sa->spp;
	auth->secParamIndicator = 0;
	if (sa->res_ind) {
		auth->secParamIndicator += 0x1;
	}
	if (sa->seqnum_ind) {
		auth->secParamIndicator += 0x2;
	}
	auth->keyID = key->key_id;
	/* set pointers to extra data used for icv generation */
	sequenceNo = auth->data;
	res = sequenceNo + (sa->seqnum_ind ? sa->seqnum_len : 0);
	icv = res + (sa->res_ind ? sa->res_len : 0);
	if (msg_pre_send(msg)) {
		return -1;
	}
	if (!sad_generate_icv(sa, key, msg, icv)) {
		return -1;
	}

	return 0;
}

/**
 * update the last received seqid
 */
void sad_set_last_seqid(struct config *cfg,
			int spp, Integer32 seqid)
{
	struct security_association* sa;
	/* immediately return if security is not configured */
	if (spp < 0) {
		return;
	}
	/* retrieve sa specified by spp */
	sa = sad_get_association(cfg, spp);
	if (!sa) {
		return;
	}

	sa->last_seqid = (seqid == -1) ? seqid : (UInteger16) seqid;
}

/**
 * confirm seqid from inbound message header is with in seqid window.
 */
static int sad_check_seqid(struct ptp_message *msg,
			   Integer32 last_seqid,
			   UInteger16 seqid_window)
{
	UInteger16 new_seqid;
	/* do not check seqid if seqid_window is zero */
	if (seqid_window < 1) {
		return 0;
	}

	/* (for now) only check seqid on sync/followup msgs */
	switch (msg_type(msg)) {
	case SYNC:
	case FOLLOW_UP:
		new_seqid = msg->header.sequenceId;
		/* last_seqid < 0 means unitialized */
		if (last_seqid < 0) {
			return 0;
		/* verify received seqid is greater than last */
		/* use mod(uint16) to handle wrap within window */
		} else if (new_seqid < (UInteger16)(last_seqid + 1) &&
			   (UInteger16)(new_seqid + seqid_window) <
			   (UInteger16)(last_seqid + 1 + seqid_window)) {
			pr_debug("replayed seqid: received seqid %u "
				 "smaller than last %u",
				 new_seqid, last_seqid);
			return -EBADMSG;
		/* verify received seqid is less than seqid window */
		/* use mod(uint16) to handle wrap within window */
		} else if (new_seqid > (UInteger16)(last_seqid + seqid_window) &&
			   (UInteger16)(new_seqid + seqid_window) >
			   (UInteger16)(last_seqid + 2 * seqid_window)) {
			pr_debug("replayed seqid: received seqid %u "
				 "beyond seqid_window %u + %d",
				 new_seqid, last_seqid, seqid_window);
			return -EBADMSG;
		}
		break;
	default:
		break;
	}
	return 0;
}

/**
 * iterate through attached tlvs on inbound messages and process any auth tlvs
 * this includes:
 * 1. confirm received spp, secParamIndictor and key match our expectations
 * 2. zero mutable fields (correction field) if mutable is set
 * 3. generate icv of inbound message using key from sa with matching key id
 * 4. compare our icv with icv attached to message
 */
static int sad_check_auth_tlv(struct security_association *sa,
			      struct ptp_message *msg,
			      struct ptp_message *raw)
{
	struct tlv_extra *extra;
	struct authentication_tlv *auth;
	struct security_association_key *key;
	void *icv;
	int err = -EPROTO;
	size_t data_len, tlv_count = 0;
	Enumeration16 last_tlv = 0;
	/* process any/all authentication tlvs now */
	TAILQ_FOREACH(extra, &msg->tlv_list, list) {
		tlv_count++;
		last_tlv = extra->tlv->type;
		if (extra->tlv->type != TLV_AUTHENTICATION) {
			continue;
		}
		auth = (struct authentication_tlv *) extra->tlv;

		/* verify spp matches expectations */
		if (sa->spp != auth->spp) {
			pr_debug("sa %u: received auth tlv"
				 " with unexpected spp %u",
				 sa->spp, auth->spp);
			return -EBADMSG;
		}

		/* verify res, seqnum, disclosedKey field indicators match expectations */
		if ((sa->res_ind != ((auth->secParamIndicator & 0x1) != 0)) ||
		    (sa->seqnum_ind != ((auth->secParamIndicator & 0x2) != 0)) ||
		    (sa->immediate_ind == ((auth->secParamIndicator & 0x4) != 0))) {
			pr_debug("sa %u: received auth tlv"
				 " with unexpected sec param %d",
				 sa->spp, auth->secParamIndicator);
			return -EBADMSG;
		}

		/* retrieve key specified in keyID field */
		key = sad_get_key(sa, auth->keyID);
		if (!key) {
			pr_debug("sa %u: received auth tlv"
				 " with unexpected key %u",
				 sa->spp, auth->keyID);
			return -EBADMSG;
		}

		/* verify TLV length matches expectation */
		if (auth->length != sad_get_auth_tlv_len(sa, key->icv->digest_len) - 4) {
			pr_debug("sa %u: received auth tlv"
				 " with unexpected length",
				 sa->spp);
			return -EBADMSG;
		}

		/* set correction to zero if mutable fields are allowed */
		if (sa->mutable) {
			if (raw->header.correction != 0) {
				pr_debug("sa %u: mutable set: correction field"
					 " not secured by auth tlv", sa->spp);
			}
			raw->header.correction = 0;
		}

		/* determine start address of icv and data length */
		icv = (char *) auth + sad_get_auth_tlv_len(sa, 0);
		data_len = (char *) icv - (char *) msg;

		if (sad_verify(key->data, raw, data_len,
			     icv, key->icv->digest_len) != 0) {
			pr_debug("sa %u: icv compare failed",
				 sa->spp);
			return -EBADMSG;
		}
		err = 0;
	}
	/* enforce an authentication tlv be last */
	if (tlv_count == 0) {
		pr_debug("sa %u: received message with no auth tlv",
			 sa->spp);
		return -EBADMSG;
	}
	if (last_tlv != TLV_AUTHENTICATION) {
		pr_debug("sa %u: received %u tlv after auth tlv",
			 sa->spp, last_tlv);
		return -EBADMSG;
	}

	return err;
}

/**
 * Perform any necessary authentication processing on inbound messages
 * This includes:
 * 1. retrieve security assocation specified to port
 * 2. check header seqid for SYNC/FOLLOWUP
 * 3. check attached auth tlvs
 */
int sad_process_auth(struct config *cfg, int spp,
		     struct ptp_message *msg,
		     struct ptp_message *raw)
{
	struct security_association* sa;
	int err = 0;
	/* immediately return if security is not configured */
	if (spp < 0) {
		return err;
	}
	/* retrieve sa specified by spp */
	sa = sad_get_association(cfg, spp);
	if (!sa) {
		return -EPROTO;
	}
	/* check seqid in header first (sync/followup only) */
	err = sad_check_seqid(msg, sa->last_seqid, sa->seqid_window);
	if (err) {
		return err;
	}
	/* detect and process any auth tlvs  */
	err = sad_check_auth_tlv(sa, msg, raw);
	return err;
}

static void sad_destroy_association(struct security_association *sa)
{
	struct security_association_key *key;
	while ((key = STAILQ_FIRST(&sa->keys))) {
		STAILQ_REMOVE_HEAD(&sa->keys, list);
		sad_deinit_mac(key->data);
		free(key);
	}
}

void sad_destroy(struct config *cfg)
{
	struct security_association *sa;
	while ((sa = STAILQ_FIRST(&cfg->security_association_database))) {
		sad_destroy_association(sa);
		STAILQ_REMOVE_HEAD(&cfg->security_association_database, list);
		free(sa);
	}
}

static int sad_config_switch_security_association(struct config *cfg,
						  int spp, size_t line_num)
{
	struct security_association *sa;
	current_sa = NULL;

	if (spp < 0 || spp > UINT8_MAX) {
		pr_err("sa_file: line %zu: spp %d is out of range. "
			"Must be in the range %d to %d - ignoring",
			line_num, spp, 0, UINT8_MAX);
		return -1;
	}
	STAILQ_FOREACH(sa, &cfg->security_association_database, list) {
		if (sa->spp == spp) {
			pr_err("line %zu: sa %u already taken"
				" - ignoring", line_num, spp);
			return -1;
		}
	}
	sa = calloc(1, sizeof(*sa));
	if (!sa) {
		pr_err("low memory");
		return -1;
	}
	STAILQ_INIT(&sa->keys);
	sa->spp = spp;
	/* set defaults */
	sa->seqnum_ind = FALSE;
	sa->seqnum_len = 0;
	sa->seqid_window = 3;
	sa->immediate_ind = TRUE;
	sa->res_ind = FALSE;
	sa->res_len = 0;
	sa->mutable = FALSE;
	sa->last_seqid = -1;

	STAILQ_INSERT_TAIL(&cfg->security_association_database, sa, list);
	current_sa = sa;

	return 0;
}

static int sad_config_sa_seqnum_len(int seqnum_len, size_t line_num)
{
	if (!current_sa) {
		pr_err("sa_file: line %zu: missing spp - ignoring",
			line_num);
		return -1;
	}

	if (seqnum_len > 0) {
		pr_err("sa_file: line %zu: seqnum field not supported (yet)"
			" - ignoring", line_num);
		return -1;
	}

	current_sa->seqnum_ind = (seqnum_len > 0);
	current_sa->seqnum_len = (seqnum_len > 0) ? seqnum_len : 0;

	return 0;
}

static int sad_config_sa_seqid_window(int seqid_window, size_t line_num)
{
	if (!current_sa) {
		pr_err("sa_file: line %zu: missing spp - ignoring",
			line_num);
		return -1;
	}

	if (seqid_window < 0 || seqid_window > UINT16_MAX / 2) {
		pr_err("sa_file: line %zu: seqid_window %d out of range"
			" - ignoring", line_num, seqid_window);
		return -1;
	}

	current_sa->seqid_window = (seqid_window > 0) ? seqid_window : 0;

	return 0;
}

static int sad_config_sa_res_len(int res_len, size_t line_num)
{
	if (!current_sa) {
		pr_err("sa_file: line %zu: missing spp - ignoring",
			line_num);
		return -1;
	}

	if (res_len > 0) {
		pr_err("sa_file: line %zu: res field not supported (yet)"
			" - ignoring", line_num);
		return -1;
	}

	current_sa->res_ind = (res_len > 0);
	current_sa->res_len = (res_len > 0) ? res_len : 0;

	return 0;
}

static int sad_config_sa_mutable(int mutable, size_t line_num)
{
	if (!current_sa) {
		pr_err("sa_file: line %zu: missing spp - ignoring",
			line_num);
		return -1;
	}

	if (mutable < 0 || mutable > 1) {
		pr_err("sa_file: line %zu: allow_mutable must be 0 or 1"
			" - ignoring", line_num);
		return -1;
	}

	current_sa->mutable = (mutable > 0);

	return 0;
}

static int sad_config_parse_key(char *line, size_t line_num,
				size_t *id, const char **type,
				size_t *len, char **key)
{
	char *token, *tokens[5];
	int count = 0;

	token = strtok(line, " \t");
	while (token != NULL && count < 5) {
		tokens[count] = token;
		count++;
		token = strtok(NULL, " \t");
	}
	if (count < 3 || count > 4) {
		pr_err("sa_file: line %zu: invalid key line:"
			" requires format 'id type [len] str'"
			" - ignoring", line_num);
		return 0;
	}

	if (sscanf(tokens[0], "%zu", id) != 1) {
		pr_err("sa_file: line %zu: invalid key_id %s"
			" - ignoring", line_num, tokens[0]);
		return 0;
	}
	*type = tokens[1];
	if (count == 3) {
		*len = 0;
		*key = tokens[2];
	} else {
		if (sscanf(tokens[2], "%zu", len) != 1) {
			pr_err("sa_file: line %zu: invalid key_len %s"
				" - ignoring", line_num, tokens[2]);
			return 0;
		}
		*key = tokens[3];
	}

	return 1;
}

static int sad_config_security_association_key(size_t key_id, const char *icv_str,
					       size_t spec_len, char *key_str,
					       size_t line_num)
{
	struct security_association_key *key;
	struct integrity_alg_info *icv;
	size_t key_len = 0;

	if (!current_sa) {
		pr_err("sa_file: line %zu: missing spp - ignoring",
			line_num);
		return -1;
	}
	/* process key_id */
	if (key_id < 1 || key_id > UINT32_MAX) {
		pr_err("sa_file: line %zu: key_id %zu is out of range. "
			"Must be in the range %u to %u - ignoring",
			line_num, key_id, 1, UINT32_MAX);
		return -1;
	}
	STAILQ_FOREACH(key, &current_sa->keys, list) {
		if (key->key_id == key_id) {
			pr_err("sa_file: line %zu: key_id %zu already taken"
				" - ignoring", line_num, key_id);
			return -1;
		}
	}
	key = calloc(1, sizeof(*key));
	if (!key) {
		pr_err("low memory");
		return -1;
	}
	key->key_id = key_id;
	/* process icv_str */
	for (icv = supported_algorithms; icv->label; icv++) {
		if (!strcasecmp(icv->label, icv_str)) {
			key->icv = icv;
			break;
		}
	}
	if (!icv->label) {
		pr_err("sa_file: line %zu: unsupported algorithm: %s"
			" - ignoring", line_num, icv_str);
		free(key);
		return -1;
	}
	/* process key_str */
	key_len = strlen(key_str);
	if (strncmp(key_str, "ASCII:", 6) == 0) {
		memmove(key_str, key_str + 6, key_len - 6);
		key_len = key_len - 6;
	} else if (strncmp(key_str, "HEX:", 4) == 0) {
		memmove(key_str, key_str + 4, key_len - 4);
		key_len = key_len - 4;
		if (key_len % 2) {
			pr_err("sa_file: line %zu: invalid key length %zu,"
				" hex keys must have even length"
				" - ignoring", line_num, key_len);
			free(key);
			return -1;
		}
		for (int i = 0; i < key_len; i += 2) {
			const char hex_pair[3] = { key_str[i], key_str[i + 1], '\0' };
			long value = strtol(hex_pair, NULL, 16);
			key_str[i / 2] = (char) value;
		}
		key_len = key_len / 2;
	} else if (strncmp(key_str, "B64:", 4) == 0) {
		if(!base64_decode(key_str + 4, key_len - 4, key_str, &key_len)) {
			pr_err("sa_file: line %zu: invalid Base64 key"
				" - ignoring", line_num);
			free(key);
			return -1;
		}
	}
	if (spec_len > 0 && key_len != spec_len) {
		pr_err("sa_file: line %zu: invalid key length %zu,"
			" does not match specified length %zu - ignoring",
			line_num, key_len, spec_len);
		free(key);
		return -1;
	}
	if (icv->key_len > 0 && key_len != icv->key_len) {
		pr_err("sa_file: line %zu: invalid key length %zu,"
			" does not match cipher length %zu - ignoring",
			line_num, key_len, icv->key_len);
		free(key);
		return -1;
	}
	if (key_len < 1) {
		pr_err("sa_file: line %zu: invalid key length %zu,"
			" positive key_len required - ignoring",
			line_num, key_len);
		free(key);
		return -1;
	}
	if (icv->digest_len > MAX_DIGEST_LENGTH ||
	    icv->digest_len < 2 ||
	    icv->digest_len % 2 ) {
		pr_err("BUG: sa_file: line %zu: even digest length"
			" from %u and %u required - ignoring",
			line_num, 2, MAX_DIGEST_LENGTH);
		free(key);
		return -1;
	}
	/* initialize mac function */
	key->data = sad_init_mac(icv->type, (unsigned char *) key_str, key_len);
	if (!key->data) {
		pr_err("sa_file: line %zu: key %zu init failed"
			" - ignoring", line_num, key_id);
		free(key);
		return -1;
	}
	memset(&key_str, 0, sizeof(key_str));

	STAILQ_INSERT_TAIL(&current_sa->keys, key, list);

	return 0;
}

static int sad_parse_security_association_line(struct config *cfg,
						char *line, size_t line_num)
{
	int spp, seqnum_len, seqid_window, res_len, mutable;
	size_t key_id, key_len;
	char *key_value;
	const char *key_type;

	if (sscanf(line, " spp %d", &spp) == 1)
		return sad_config_switch_security_association(cfg, spp, line_num);

	if (sscanf(line, " seqnum_length %d", &seqnum_len) == 1)
		return sad_config_sa_seqnum_len(seqnum_len, line_num);

	if (sscanf(line, " seqid_window %d", &seqid_window) == 1)
		return sad_config_sa_seqid_window(seqid_window, line_num);

	if (sscanf(line, " res_length %d", &res_len) == 1)
		return sad_config_sa_res_len(res_len, line_num);

	if (sscanf(line, " allow_mutable %d", &mutable) == 1)
		return sad_config_sa_mutable(mutable, line_num);

	if (sad_config_parse_key(line, line_num, &key_id, &key_type, &key_len, &key_value))
		return sad_config_security_association_key(key_id, key_type, key_len,
							   key_value, line_num);

	return 0;
}

int sad_create(struct config *cfg)
{
	char buf[1024], *line, *c;
	size_t line_num;

	const char *sa_file = config_get_string(cfg, NULL, "sa_file");
	if (sa_file == NULL || strlen(sa_file) == 0) {
		return 0;
	}

#if !defined (HAVE_NETTLE) && !defined (HAVE_GNUTLS) && \
    !defined (HAVE_GNUPG) && !defined (HAVE_OPENSSL)
	pr_err("sa_file set but security not supported");
	return -1;
#endif

	FILE *fp = fopen(sa_file, "r");
	if (!fp) {
		pr_err("failed to open sa_file %s: %m", sa_file);
		return -1;
	}

	/* destroy current sad if already configured */
	sad_destroy(cfg);

	for (line_num = 1; fgets(buf, sizeof(buf), fp); line_num++) {
		c = buf;
		/* skip whitespace characters */
		while (isspace(*c))
			c++;
		/* ignore empty lines and comments */
		if (*c == '#' || *c == '\n' || *c == '\0')
			continue;

		line = c;
		/* remove trailing whitespace characters and \n */
		c += strlen(line) - 1;
		while (c > line && (*c == '\n' || isspace(*c))) {
			*c-- = '\0';
		}
		if (!strcasecmp(line, "[security_association]")) {
			current_sa = NULL;
			continue;
		}
		/* remove associated sa and continue if a config line fails */
		if (sad_parse_security_association_line(cfg, line, line_num)) {
			if (current_sa != NULL) {
				pr_debug("discarding sa %u", current_sa->spp);
				sad_destroy_association(current_sa);
				STAILQ_REMOVE(&cfg->security_association_database,
						current_sa, security_association, list);
				free(current_sa);
				current_sa = NULL;
			}
			continue;
		}
	}

	fclose(fp);
	return 0;
}

int sad_readiness_check(int spp, size_t active_key_id, struct config *cfg)
{
        struct security_association *sa;
        if (spp < 0 && active_key_id < 1) {
                return 0;
        }
#if !defined (HAVE_NETTLE) && !defined (HAVE_GNUTLS) && \
    !defined (HAVE_GNUPG) && !defined (HAVE_OPENSSL)
        if (spp >= 0 || active_key_id > 0) {
                pr_err("spp or active_key_id set but security not supported");
                return -1;
        }
#endif
        if (spp >= 0) {
                if (!config_get_string(cfg, NULL, "sa_file")) {
                        pr_err("sa_file required when spp set");
                        return -1;
                }
                if (STAILQ_EMPTY(&cfg->security_association_database)) {
                        pr_err("spp set but sad is empty");
                        return -1;
                }
                sa = sad_get_association(cfg, spp);
                if (!sa) {
                        pr_err("spp set but sa %u not defined", spp);
                        return -1;
                }
                if (active_key_id < 1) {
                        pr_err("active_key_id required when spp set");
                        return -1;
                } else {
                        if (!sad_get_key(sa, active_key_id)) {
                                pr_err("sa %u: active_key_id set but key %zu"
                                        " not defined", spp, active_key_id);
                                return -1;
                        }
                }
        } else {
                if (active_key_id > 0) {
                        pr_err("spp required when active_key_id set");
                        return -1;
                }
        }
        return 0;
}
