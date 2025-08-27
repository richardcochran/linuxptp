
/**
 * @file sad_wolfcrypt.c
 * @brief Security Association Database wolfcrypt functions
 * @note Copyright (C) 2025 Alex Gebhard <alexander.gebhard@marquette.edu>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

#define MAX_HEX_OUTPUT_LEN 1024
#define MAX_KEY_LEN 1024

struct mac_data {
    Hmac *hmac;
    Cmac *cmac;
    int is_cmac;
    unsigned char key[MAX_KEY_LEN];
    int key_len;
};

void print_hex_array(const unsigned char *arr, size_t len) {
    if (!arr || len == 0 || len * 2 + 1 > MAX_HEX_OUTPUT_LEN) {
        pr_err("Invalid input to print_hex_array");
        return;
    }

    char output[(len * 2) + 1];
    char *ptr = output;

    for (size_t i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%02X", arr[i]);
    }

    *ptr = '\0';
    pr_err("%s", output);
}

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
                              const unsigned char *key, size_t key_len)
{
    if (!key || key_len == 0 || key_len > MAX_KEY_LEN) {
        pr_err("Invalid key or key length");
        return NULL;
    }

    if (wolfCrypt_Init() != 0) {
        pr_err("wolfCrypt initialization failed");
        return NULL;
    }

    struct mac_data *mac_data = calloc(1, sizeof(*mac_data));
    if (!mac_data) {
        pr_err("Memory allocation for mac_data failed");
        wolfCrypt_Cleanup();
        return NULL;
    }

    switch (algorithm) {
        case HMAC_SHA256_128:
        case HMAC_SHA256:
            mac_data->hmac = calloc(1, sizeof(Hmac));
            if (!mac_data->hmac) {
                pr_err("Memory allocation for HMAC failed");
                free(mac_data);
                wolfCrypt_Cleanup();
                return NULL;
            }
            if (wc_HmacSetKey(mac_data->hmac, SHA256, key, (word32)key_len) != 0) {
                pr_err("Failed to set HMAC key");
                sad_deinit_mac(mac_data);
                return NULL;
            }
            mac_data->is_cmac = 0;
            break;
	case CMAC_AES128:
        case CMAC_AES256:
            mac_data->cmac = calloc(1, sizeof(Cmac));
            if (!mac_data->cmac) {
                pr_err("Memory allocation for CMAC failed");
                free(mac_data);
                wolfCrypt_Cleanup();
                return NULL;
            }
            if (wc_InitCmac(mac_data->cmac, key, key_len, 1, NULL) != 0) {
                pr_err("Failed to set CMAC key");
                sad_deinit_mac(mac_data);
                return NULL;
            }
            
	    if (key_len <= MAX_KEY_LEN) {
        	memcpy(mac_data->key, key, key_len);
    	    } else {
	    	return NULL;
    	    }
	    mac_data->is_cmac = 1;
	    mac_data->key_len = key_len;
            break;

        default:
            pr_err("Unknown integrity algorithm");
            sad_deinit_mac(mac_data);
            return NULL;
    }

    return mac_data;
}

void sad_deinit_mac(struct mac_data *mac_data)
{
    if (!mac_data)
        return;

    if (mac_data->hmac) {
        free(mac_data->hmac);
        mac_data->hmac = NULL;
    }

    if (mac_data->cmac) {
        free(mac_data->cmac);
        mac_data->cmac = NULL;
    }

    free(mac_data);
    wolfCrypt_Cleanup();
}

int sad_hash(struct mac_data *mac_data,
             const void *data, size_t data_len,
             unsigned char *mac, size_t mac_len)
{
    if (!mac_data || !data || !mac || data_len == 0 || mac_len == 0) {
        pr_err("Invalid input to sad_hash");
        return 0;
    }

    if (mac_data->is_cmac) {
        if (mac_len > AES_BLOCK_SIZE || mac_len > MAX_DIGEST_LENGTH) {
            pr_err("mac_len exceeds CMAC size");
            return 0;
        }

	int ret = 0;
        if ( (ret = wc_CmacUpdate(mac_data->cmac, data, (word32)data_len)) != 0) {
            
	    pr_err("CMAC update failed with code 0x%08X", ret);
            return 0;
        }

        if (wc_CmacFinal(mac_data->cmac, mac, &mac_len) != 0) {
            pr_err("CMAC finalization failed");
            return 0;
        }

	if (wc_InitCmac(mac_data->cmac, mac_data->key, mac_data->key_len, WC_CMAC_AES, NULL) != 0) {
	    pr_err("CMAC initialization failed");
            return 0;
	}

        return mac_len;
    } else {
        const size_t digest_len = SHA256_DIGEST_SIZE;
        if (mac_len > digest_len || mac_len > MAX_DIGEST_LENGTH) {
            pr_err("mac_len exceeds HMAC size");
            return 0;
        }

        if (wc_HmacUpdate(mac_data->hmac, data, (word32)data_len) != 0) {
            pr_err("HMAC update failed");
            return 0;
        }

        if (wc_HmacFinal(mac_data->hmac, mac) != 0) {
            pr_err("HMAC finalization failed");
            return 0;
        }

        return mac_len;
    }
}

int sad_verify(struct mac_data *mac_data,
               const void *data, size_t data_len,
               unsigned char *mac, size_t mac_len)
{
    unsigned char digest_buf[MAX_DIGEST_LENGTH];

    if (!mac || mac_len == 0) {
        pr_err("Invalid MAC input to sad_verify");
        return -1;
    }

    if (!sad_hash(mac_data, data, data_len, digest_buf, mac_len)) {
        pr_err("Failed to compute hash for verification");
        return -1;
    }

    return XMEMCMP(digest_buf, mac, mac_len);
}

