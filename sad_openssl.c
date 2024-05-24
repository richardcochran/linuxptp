/**
 * @file sad_openssl.c
 * @brief Security Association Database openssl functions
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

struct mac_data {
	EVP_MAC *algorithm;
	EVP_MAC_CTX *context;
};

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len)
{
	int err;
	size_t length;

	const char *name;
	char *param, *algo;
	EVP_MAC *mac_algorithm;
	EVP_MAC_CTX *context;
	OSSL_PARAM params[2];
	EVP_CIPHER *cipher;
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
		name = "HMAC";
		param = "digest";
		algo = "SHA-256";
		break;
	case CMAC_AES128:
		name = "CMAC";
		param = "cipher";
		algo = "AES-128-CBC";
		break;
	case CMAC_AES256:
		name = "CMAC";
		param = "cipher";
		algo = "AES-256-CBC";
		break;
	default:
		pr_err("BUG: unknown algorithm");
		return NULL;
	}
	/* verify key length matches for cmac only */
	switch (algorithm) {
	case CMAC_AES128:
	case CMAC_AES256:
		cipher = EVP_CIPHER_fetch(NULL, algo, NULL);
		length = EVP_CIPHER_get_key_length(cipher);
		EVP_CIPHER_free(cipher);
		if (key_len != length) {
			pr_err("BUG: cipher key_len does not match");
			return NULL;
		}
		break;
	default:
		break;
	}
	mac_algorithm = EVP_MAC_fetch(NULL, name, NULL);
	if (!mac_algorithm) {
		pr_err("EVP_MAC_fetch() failed");
		return NULL;
	}
	context = EVP_MAC_CTX_new(mac_algorithm);
	if (!context) {
		pr_err("EVP_MAC_CTX_new() failed");
		EVP_MAC_free(mac_algorithm);
		return NULL;
	}
	params[0] = OSSL_PARAM_construct_utf8_string(param, algo, 0);
	params[1] = OSSL_PARAM_construct_end();
	err = EVP_MAC_CTX_set_params(context, params);
	if (err == 0) {
		pr_err("EVP_MAC_CTX_set_params() failed");
		EVP_MAC_free(mac_algorithm);
		EVP_MAC_CTX_free(context);
		return NULL;
	}

	/* initialize context */
	err = EVP_MAC_init(context, key, key_len, NULL);
	if (err == 0) {
		pr_err("EVP_MAC_init() failed");
		EVP_MAC_free(mac_algorithm);
		EVP_MAC_CTX_free(context);
		return NULL;
	}
	/* initialize mac_data */
	mac_data = calloc(1, sizeof(*mac_data));
	if (!mac_data) {
		EVP_MAC_free(mac_algorithm);
		EVP_MAC_CTX_free(context);
		return NULL;
	}
	mac_data->algorithm = mac_algorithm;
	mac_data->context = context;

	return mac_data;
}

void sad_deinit_mac(struct mac_data *data)
{
	EVP_MAC_free(data->algorithm);
	EVP_MAC_CTX_free(data->context);
	free(data);
}

static inline int sad_update_mac(struct mac_data *mac_data,
				 const void *data, size_t data_len,
				 unsigned char *mac, size_t mac_len)
{
	int err;
	size_t digest_len;

	/* confirm mac length is within buffer size */
	if (mac_len > MAX_DIGEST_LENGTH) {
		pr_err("BUG: mac_len larger than buffer");
		return 0;
	}

	/* update data and retrieve mac */
	err = EVP_MAC_init(mac_data->context, NULL, 0, NULL);
	if (err == 0) {
		pr_err("EVP_MAC_init() failed");
		return 0;
	}
	err = EVP_MAC_update(mac_data->context, data, data_len);
	if (err == 0) {
		pr_err("EVP_MAC_update() failed");
		return 0;
	}
	err = EVP_MAC_final(mac_data->context, mac,
			    &digest_len, MAX_DIGEST_LENGTH);
	if (err == 0) {
		pr_err("EVP_MAC_final() failed");
		return 0;
	}

	/* confirm mac length is within library support */
	if (mac_len > digest_len) {
		pr_err("BUG: mac_len larger than library support");
		return 0;
	}

	return 1;
}

int sad_hash(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	unsigned char digest_buffer[MAX_DIGEST_LENGTH];

	/* update data and retrieve mac */
	if (!sad_update_mac(mac_data, data, data_len,
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

	/* update data and retrieve mac */
	if (!sad_update_mac(mac_data, data, data_len,
			    digest_buffer, mac_len)) {
		return -1;
	}

	/* compare calculated with received */
	return CRYPTO_memcmp(digest_buffer, mac, mac_len);
}
