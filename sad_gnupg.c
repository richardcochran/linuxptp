/**
 * @file sad_gnupg.c
 * @brief Security Association Database gnupg functions
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <gcrypt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

struct mac_data {
	int algorithm;
	gcry_mac_hd_t handle;
};

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len)
{
	gcry_error_t err;
	gcry_mac_hd_t handle;
	int mac_algorithm;
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
		mac_algorithm = GCRY_MAC_HMAC_SHA256;
		break;
	case CMAC_AES128:
	case CMAC_AES256:
		mac_algorithm = GCRY_MAC_CMAC_AES;
		break;
	default:
		pr_err("BUG: unknown algorithm");
		return NULL;
	}

	/* verify key length matches for cmac only */
	switch (algorithm) {
	case CMAC_AES128:
		if (key_len != 16) {
			pr_err("BUG: cipher key_len does not match");
			return NULL;
		}
		break;
	case CMAC_AES256:
		if (key_len != 32) {
			pr_err("BUG: cipher key_len does not match");
			return NULL;
		}
		break;
	default:
		break;
	}

	/* initialize handle and set key */
	err = gcry_mac_open(&handle, mac_algorithm, 0, NULL);
	if (err != GPG_ERR_NO_ERROR) {
		pr_err("gcry_mac_open() failed");
		return NULL;
	}
	err = gcry_mac_setkey(handle, key, key_len);
	if (err != GPG_ERR_NO_ERROR) {
		pr_err("gcry_mac_setkey() failed");
		gcry_mac_close(handle);
		return NULL;
	}
	/* initialize mac_data */
	mac_data = calloc(1, sizeof(*mac_data));
	if (!mac_data) {
		gcry_mac_close(handle);
		return NULL;
	}
	mac_data->algorithm = mac_algorithm;
	mac_data->handle = handle;

	return mac_data;
}

void sad_deinit_mac(struct mac_data *data)
{
	gcry_mac_close(data->handle);
	free(data);
}

static inline int sad_write_mac(struct mac_data *mac_data,
			      const void *data, size_t data_len,
			      size_t mac_len)
{
	gcry_error_t err;
	size_t digest_len;

	/* confirm mac length is within library support */
	digest_len = gcry_mac_get_algo_maclen(mac_data->algorithm);
	if (mac_len > digest_len) {
		pr_err("BUG: mac_len larger than library support");
		return 0;
	}

	/* confirm mac length is within buffer size */
	if (mac_len > MAX_DIGEST_LENGTH) {
		pr_err("BUG: mac_len larger than buffer");
		return 0;
	}

	/* update data */
	err = gcry_mac_reset(mac_data->handle);
	if (err != GPG_ERR_NO_ERROR) {
		pr_err("gcry_mac_reset() failed");
		return 0;
	}
	err = gcry_mac_write(mac_data->handle, data, data_len);
	if (err != GPG_ERR_NO_ERROR) {
		pr_err("gcry_mac_write() failed");
		return 0;
	}

	return 1;
}

int sad_hash(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	gcry_error_t err;

	/* write data */
	if (!sad_write_mac(mac_data, data, data_len, mac_len)) {
		return 0;
	}

	/* retrieve mac */
	err = gcry_mac_read(mac_data->handle, mac, &mac_len);
	if (err != GPG_ERR_NO_ERROR) {
		pr_err("gcry_mac_read() failed");
		return 0;
	}

	return mac_len;
}

int sad_verify(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	gcry_error_t err;

	/* write data */
	if (!sad_write_mac(mac_data, data, data_len, mac_len)) {
		return -1;
	}

	/* compare calculated with received */
	err = gcry_mac_verify(mac_data->handle, mac, mac_len);
	if (err == GPG_ERR_CHECKSUM) {
		pr_debug("gcry_mac_verify() wrong ICV");
		return -1;
	} else if (err != GPG_ERR_NO_ERROR) {
		pr_err("gcry_mac_verify() failed");
		return -1;
	}

	return 0;
}
