/**
 * @file sad_gnutls.c
 * @brief Security Association Database gnutls functions
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <gnutls/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

static int mac_count = -1;

struct mac_data {
	gnutls_mac_algorithm_t algorithm;
	gnutls_hmac_hd_t handle;
};

static int sad_init_gnutls(void)
{
	int err = 0;

	if (mac_count >= 0) {
		return 0;
	}

	err = gnutls_global_init();
	if (err < 0) {
		pr_err("gnutls_global_init() failed: %s",
			gnutls_strerror(err));
		return -1;
	}

	mac_count = 0;
	return 0;
}

static void sad_deinit_gnutls(void)
{
	if (mac_count == 0) {
		gnutls_global_deinit();
		mac_count = -1;
	}
}

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len)
{
	int err, length;
	gnutls_hmac_hd_t handle;
	gnutls_mac_algorithm_t mac_algorithm;
	struct mac_data *mac_data;

	/* initialize gnutls if not already */
	if (mac_count < 0) {
		if (sad_init_gnutls() < 0) {
			return NULL;
		}
	}

	/* verify key length */
	if (key_len == 0) {
		pr_err("BUG: key_len is zero");
		sad_deinit_gnutls();
		return NULL;
	}

	/* retrieve mac algorithm */
	switch (algorithm) {
	case HMAC_SHA256_128:
	case HMAC_SHA256:
		mac_algorithm = GNUTLS_MAC_SHA256;
		break;
	case CMAC_AES128:
		mac_algorithm = GNUTLS_MAC_AES_CMAC_128;
		break;
	case CMAC_AES256:
		mac_algorithm = GNUTLS_MAC_AES_CMAC_256;
		break;
	default:
		pr_err("BUG: unknown algorithm");
		sad_deinit_gnutls();
		return NULL;
	}

	/* retrieve mac key length */
	length = gnutls_hmac_get_key_size(mac_algorithm);
	if (length < 0) {
		sad_deinit_gnutls();
		return NULL;
	}
	/* verify key length matches for cmac only */
	switch (algorithm) {
	case CMAC_AES128:
	case CMAC_AES256:
		if (key_len != length) {
			pr_err("BUG: cipher key_len does not match");
			sad_deinit_gnutls();
			return NULL;
		}
		break;
	default:
		break;
	}

	/* initialize handle and set key */
	err = gnutls_hmac_init(&handle, mac_algorithm, key, key_len);
	if (err < 0) {
		pr_err("gnutls_hmac_init() failed: %s",
			gnutls_strerror(err));
		sad_deinit_gnutls();
		return NULL;
	}
	/* initialize mac_data */
	mac_data = calloc(1, sizeof(*mac_data));
	if (!mac_data) {
		sad_deinit_gnutls();
		return NULL;
	}
	mac_data->algorithm = mac_algorithm;
	mac_data->handle = handle;

	mac_count++;

	return mac_data;
}

void sad_deinit_mac(struct mac_data *data)
{
	gnutls_hmac_deinit(data->handle, NULL);
	free(data);

	mac_count--;

	sad_deinit_gnutls();
}

static inline int sad_output_mac(struct mac_data *mac_data,
				 const void *data, size_t data_len,
				 unsigned char *mac, size_t mac_len)
{
	size_t digest_len;

	/* confirm mac length is within library support */
	digest_len = gnutls_hmac_get_len(mac_data->algorithm);
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
	if (gnutls_hmac(mac_data->handle, data, data_len) < 0) {
		gnutls_hmac_output(mac_data->handle, mac);
		pr_err("gnutls_hmac() failed");
		return 0;
	}
	gnutls_hmac_output(mac_data->handle, mac);

	return 1;
}

int sad_hash(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	unsigned char digest_buffer[MAX_DIGEST_LENGTH];

	/* update data and output mac */
	if (!sad_output_mac(mac_data, data, data_len,
			    digest_buffer, mac_len)) {
		return 0;
	}

	/* move mac to desired location */
	memcpy(mac, digest_buffer, mac_len);

	return mac_len;
}

int sad_verify(struct mac_data *mac_data,
	       const void *data, size_t data_len,
	       unsigned char *mac, size_t mac_len)
{
	unsigned char digest_buffer[MAX_DIGEST_LENGTH];

	/* update data and output mac */
	if (!sad_output_mac(mac_data, data, data_len,
			 digest_buffer, mac_len)) {
		return -1;
	}

	/* compare calculated with received */
	return gnutls_memcmp(digest_buffer, mac, mac_len);
}
