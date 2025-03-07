/**
 * @file sad_nettle.c
 * @brief Security Association Database nettle functions
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <wolfssl/wolfcrypt/hmac.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

struct mac_data {
	Hmac    *hmac;
};

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len)
{
	size_t i, length;
	const char *name;
	const struct Hmac *mac_algorithm = NULL;
	struct mac_data *mac_data;
	int type;

	/* verify key length */
	if (key_len == 0) {
		pr_err("BUG: key_len is zero");
		return NULL;
	}

	if (wolfCrypt_Init() != 0) {
		pr_err("BUG: wolfCrypt could not initialize");
		return NULL;
	}

	mac_data = calloc(1, sizeof(*mac_data));
	if (!mac_data) {
		return NULL;
	}

	mac_algorithm = calloc(1, sizeof(Hmac));
	if (!mac_algorithm) {
		return NULL;
	}

	mac_data->hmac = mac_algorithm;

	/* retrieve mac algorithm */
	switch (algorithm) {
	case HMAC_SHA256_128:
	case HMAC_SHA256:
		type = SHA256;
		wc_HmacSetKey(mac_algorithm, SHA256, key, key_len);
		break;
	default:
		pr_err("BUG: unknown algorithm");
		return NULL;
	}

	return mac_data;
}

void sad_deinit_mac(struct mac_data *mac_data)
{
	free(mac_data->hmac);
	free(mac_data);
	wolfCrypt_Cleanup();	
}

int sad_hash(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	size_t digest_len;

	/* confirm mac length is within library support */
	digest_len  = SHA256_DIGEST_SIZE;
	if (mac_len > digest_len) {
		pr_err("BUG: mac_len larger than library support");
		return 0;
	}

	/* confirm mac length is within buffer size */
	if (mac_len > MAX_DIGEST_LENGTH) {
		pr_err("BUG: mac_len larger than buffer");
		return 0;
	}

	wc_HmacUpdate(mac_data->hmac, data, data_len);
	wc_HmacFinal(mac_data->hmac, mac);

	return mac_len;
}

int sad_verify(struct mac_data *mac_data,
	       const void *data, size_t data_len,
	       unsigned char *mac, size_t mac_len)
{
	unsigned char digest_buf[MAX_DIGEST_LENGTH];

	/* update data and retrieve mac */
	if (!sad_hash(mac_data, data, data_len, digest_buf, mac_len)) {
		return -1;
	}

	/* compare calculated with received */
	return (XMEMCMP(digest_buf, mac, mac_len) == 0);
}
