/**
 * @file sad_nettle.c
 * @brief Security Association Database nettle functions
 * @note Copyright (C) 2024 IBM Corporation, Clay Kaiser <Clay.Kaiser@ibm.com>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#define WOLFSSL_CMAC 1

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

struct mac_data {
	int	type;
	Hmac    *hmac;
	Cmac	*cmac;
};

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
			      const unsigned char *key, size_t key_len)
{
	struct Hmac *mac_algorithm = NULL;
	struct Cmac *cmac_algorithm = NULL;
	struct mac_data *mac_data;
	int ret;

	printf("In sad_init_mac");

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

	/* retrieve mac algorithm */
	switch (algorithm) {
	case HMAC_SHA256_128:
	case HMAC_SHA256:
	        mac_algorithm = calloc(1, sizeof(Hmac));
        	if (!mac_algorithm)
                	return NULL;

		mac_data->hmac = mac_algorithm;
		mac_data->type = HMAC_SHA256;
		wc_HmacSetKey(mac_algorithm, SHA256, key, key_len);
		break;
	case CMAC_AES128:
	case CMAC_AES256:
		cmac_algorithm = calloc(1, sizeof(Cmac));
                if (!cmac_algorithm)
                        return NULL;

		mac_data->cmac = cmac_algorithm;
		mac_data->type = algorithm;
		if (algorithm == CMAC_AES128 && key_len != 16) {
			pr_err("CMAC_AES128 requires a 128-bit key");
			return NULL;
		} else if (algorithm == CMAC_AES256 && key_len != 32) {
			pr_err("CMAC_AES256 requires a 256-bit key");
                        return NULL;
		}

		ret = wc_InitCmac(cmac_algorithm, key, key_len, WC_CMAC_AES, NULL);
		if (ret)
			return NULL;

		break;
	default:
		pr_err("BUG: unknown algorithm");
		return NULL;
	}

	return mac_data;
}

void sad_deinit_mac(struct mac_data *mac_data)
{
	printf("In sad_deinit_mac");

	if (mac_data->hmac)
		free(mac_data->hmac);
	if (mac_data->cmac)
		free(mac_data->cmac);
	free(mac_data);
	wolfCrypt_Cleanup();	
}

int sad_hash(struct mac_data *mac_data,
	     const void *data, size_t data_len,
	     unsigned char *mac, size_t mac_len)
{
	printf("In sad_hash");
	if (mac_data->type == SHA256) {
		/* confirm mac length is within library support */
		if (mac_len > SHA256_DIGEST_SIZE) {
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
	} else {
		wc_CmacUpdate(mac_data->cmac, data, data_len);
		wc_CmacFinal(mac_data->cmac, mac, &mac_len);

		return mac_len;
	}
}

int sad_verify(struct mac_data *mac_data,
	       const void *data, size_t data_len,
	       unsigned char *mac, size_t mac_len)
{
	unsigned char digest_buf[MAX_DIGEST_LENGTH];
	unsigned char cmac_buf[16];

	printf("In sad_verify");

	if (mac_data->type == SHA256) {
		/* update data and retrieve mac */
		if (!sad_hash(mac_data, data, data_len, digest_buf, mac_len)) {
			return -1;
		}

		/* compare calculated with received */
        	return (XMEMCMP(digest_buf, mac, mac_len) == 0);
	} else {
		/* update data and retrieve mac */
                if (!sad_hash(mac_data, data, data_len, cmac_buf, mac_len)) {
                        return -1;
                }

                /* compare calculated with received */
                return (XMEMCMP(cmac_buf, mac, mac_len) == 0);		
	}
}
