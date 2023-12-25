/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

int HKDF_extract(const EVP_MD *md, const uint8_t *salt, size_t saltLen, const uint8_t *inKey, size_t inKeyLen, uint8_t *prKeyBuf, size_t *prKeyLen)
{
    unsigned int outLen;

    if (HMAC(md, salt, saltLen, inKey, inKeyLen, prKeyBuf, &outLen) == NULL)
        return 0;

    *prKeyLen = (size_t)outLen;

    return 1;
}

int HKDF_expand(const EVP_MD *md, const uint8_t *prKey, size_t prKeyLen, const uint8_t *info, size_t infoLen, uint8_t *outKey, size_t outKeyLen)
{
    int res = 0;
    uint8_t hashNum = 1;
    size_t hashSize = EVP_MD_size(md);
    size_t finalLen;

    // sha1 or sha256 hashAlgo = (caseExchangeRec->config == kCASEConfig_Config1) ? EVP_sha1() : EVP_sha256();
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "SHA1", NULL);

    EVP_MAC_CTX *hmac = EVP_MAC_CTX_new(mac);

    if (outKeyLen < 1 || outKeyLen > 255 * hashSize)
        goto exit;

    while (1) {
        // skip checking if it is already initialized?
        if (!EVP_MAC_init(hmac, prKey, prKeyLen, NULL))
            return 0;

        if (hashNum > 1) {
            if (!EVP_MAC_update(hmac, outKey - hashSize, hashSize))
                goto exit;
        }

        if (info != NULL && infoLen > 0) {
            if (!EVP_MAC_update(hmac, info, infoLen))
                goto exit;
        }

        if (!EVP_MAC_update(hmac, &hashNum, 1))
            goto exit;

        if (outKeyLen < hashSize)
        {
            uint8_t finalHash[EVP_MAX_MD_SIZE];

            if (!EVP_MAC_final(hmac, finalHash, &finalLen, sizeof(finalHash)))
                goto exit;

            memcpy(outKey, finalHash, outKeyLen);

            break;
        }

        if (!EVP_MAC_final(hmac, outKey, &finalLen, sizeof(outKey)))
            goto exit;

        outKey += hashSize;
        outKeyLen -= hashSize;
        hashNum++;
    }

    res = 1;

exit:
    EVP_MAC_CTX_free(hmac);
    return res;
}
