/**
 * @file sad_nettle.c
 * @brief Security Association Database nettle functions
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <nettle/hmac.h>
#include <nettle/memops.h>
#include <nettle/nettle-meta.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

struct mac_data {
	const struct nettle_mac *nettle_mac;
	void *context;
};

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len)
{
	size_t i, length;
	const char *name;
	const struct nettle_mac *mac_algorithm = NULL;
	struct mac_data *mac_data;

	/* verify key length */
	if (key_len == 0) {
		pr_err("BUG: key_len is zero");
		return NULL;
	}

	/* retrieve mac algorithm */
	switch (algorithm) {
	case HMAC_SHA256_128:
	case HMAC_SHA256:
		name = "hmac_sha256";
		break;
	case CMAC_AES128:
		name = "cmac_aes128";
		break;
	case CMAC_AES256:
		name = "cmac_aes256";
		break;
	default:
		pr_err("BUG: unknown algorithm");
		return NULL;
	}
	for (i = 0; nettle_macs[i]; i++) {
		if (!strcmp(name, nettle_macs[i]->name)) {
			mac_algorithm = nettle_macs[i];
			break;
		}

	}
	if (!mac_algorithm || !mac_algorithm->context_size || !mac_algorithm->set_key)
		return NULL;

	/* retrieve mac key length */
	length = mac_algorithm->key_size;

	/* verify key length matches for cmac only */
	switch (algorithm) {
	case CMAC_AES128:
	case CMAC_AES256:
		if (key_len != length) {
			pr_err("BUG: cipher key_len does not match");
			return NULL;
		}
		break;
	default:
		break;
	}

	/* initialize mac_data and context */
	mac_data = calloc(1, sizeof(*mac_data));
	if (!mac_data) {
		return NULL;
	}
	mac_data->nettle_mac = mac_algorithm;
	mac_data->context = calloc(1, mac_data->nettle_mac->context_size);
	if (!mac_data->context) {
		free(mac_data);
		return NULL;
	}
	/* set key */
	switch (algorithm) {
	case HMAC_SHA256_128:
	case HMAC_SHA256:
		/* not able to use mac abstraction AND any length sha key */
		hmac_sha256_set_key(mac_data->context, key_len, key);
		break;
	case CMAC_AES128:
	case CMAC_AES256:
		mac_data->nettle_mac->set_key(mac_data->context, key);
		break;
	default:
		sad_deinit_mac(mac_data);
		return NULL;
	}

	return mac_data;
}

void sad_deinit_mac(struct mac_data *mac_data)
{
	free(mac_data->context);
	free(mac_data);
}

int sad_hash(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	size_t digest_len;

	/* confirm mac length is within library support */
	digest_len = mac_data->nettle_mac->digest_size;
	if (mac_len > digest_len) {
		pr_err("BUG: mac_len larger than library support");
		return 0;
	}

	/* confirm mac length is within buffer size */
	if (mac_len > MAX_DIGEST_LENGTH) {
		pr_err("BUG: mac_len larger than buffer");
		return 0;
	}

	/* update data and retrieve mac */
	mac_data->nettle_mac->update(mac_data->context, data_len, data);
	mac_data->nettle_mac->digest(mac_data->context, mac_len, mac);

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
	return (memeql_sec(digest_buf, mac, mac_len) != 1);
}
