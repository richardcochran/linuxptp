/**
 * @file sad_private.h
 * @brief Security Association Database
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#ifndef HAVE_SAD_PRIVATE_H
#define HAVE_SAD_PRIVATE_H

#define MAX_DIGEST_LENGTH 32

#include <sys/queue.h>

#include "pdt.h"

typedef enum {
	MAC_INVALID = 0,
	HMAC_SHA256_128,
	HMAC_SHA256,
	CMAC_AES128,
	CMAC_AES256,
} integrity_alg_type;

struct integrity_alg_info {
	const char         *label;
	integrity_alg_type type; /* algorithm type - minimum HMAC-SHA256-128 */
	size_t             key_len;    /* length of key */
	size_t             digest_len; /* length of icv */
};

struct mac_data;
struct security_association_key {
	STAILQ_ENTRY(security_association_key) list;
	struct integrity_alg_info *icv;
	struct mac_data *data;    /* data for mac function */
	UInteger32 key_id;        /* symmetric key ID */
};

#if defined (HAVE_NETTLE) || defined (HAVE_GNUTLS) || \
    defined (HAVE_GNUPG) || defined (HAVE_OPENSSL)
struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len);

void sad_deinit_mac(struct mac_data *parms);

int sad_hash(struct mac_data *parms,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len);

int sad_verify(struct mac_data *mac_data,
	       const void *data, size_t data_len,
	       unsigned char *mac, size_t mac_len);

#else
static inline struct mac_data *sad_init_mac(integrity_alg_type algorithm,
					    const unsigned char *key,
					    size_t key_len)
{
	pr_err("security configured but not supported");
	return NULL;
}

static inline void sad_deinit_mac(struct mac_data *mac_data)
{
	pr_err("security configured but not supported");
	return;
}

static inline int sad_hash(struct mac_data *mac_data,
			   const void *data, size_t data_len,
			   unsigned char *mac, size_t mac_len)
{
	pr_err("security configured but not supported");
	return 0;
}

static inline int sad_verify(struct mac_data *mac_data,
			     const void *data, size_t data_len,
			     unsigned char *mac, size_t mac_len)
{
	pr_err("security configured but not supported");
	return -1;
}

#endif

#endif
