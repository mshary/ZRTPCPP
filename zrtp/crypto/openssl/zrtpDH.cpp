/*
 * Copyright 2006 - 2018, Werner Dittmann
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include <zrtp/crypto/zrtpDH.h>
#include <zrtp/libzrtpcpp/ZrtpTextData.h>
#include "openssl_compat.h"

#if defined(OPENSSL_3_API)
/* OpenSSL 3.x uses EVP_PKEY for DH and EC operations */
typedef struct {
    EVP_PKEY* pkey;
    int is_dh;  /* 1 for DH, 0 for EC */
    BIGNUM* dh_p; /* For DH: store p parameter */
    BIGNUM* dh_g; /* For DH: store g parameter */
} zrtp_evp_ctx;

#define ZRTP_DH_CTX(ctx) ((zrtp_evp_ctx*)(ctx))
#else
/* OpenSSL 1.0.x and 1.1.x use DH or EC_KEY directly */
#define ZRTP_DH_CTX(ctx) (ctx)
#endif

// extern void initializeOpenSSL();

static BIGNUM* bnP2048 = nullptr;
static BIGNUM* bnP3072 = nullptr;
static BIGNUM* bnP4096 = nullptr;

static BIGNUM* bnP2048MinusOne = nullptr;
static BIGNUM* bnP3072MinusOne = nullptr;
static BIGNUM* bnP4096MinusOne = nullptr;

static uint8_t dhinit = 0;

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
static CRITICAL_SECTION dh_init_lock;
static volatile LONG dh_init_started = 0;
#else
#include <pthread.h>
static pthread_mutex_t dh_init_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

void randomZRTP(uint8_t *buf, int32_t length)
{
//    initializeOpenSSL();
    RAND_bytes(buf, length);
}

static const uint8_t P2048[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t P3072[] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t P4096[] =
{
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

ZrtpDH::ZrtpDH(const char* type) {

    uint8_t random[64];
    
    ctx = nullptr;
    pkType = -1;

    if (type == nullptr) {
        return;
    }

    // Well - the algo type is only 4 char thus cast to int32 and compare
    if (*(int32_t*)type == *(int32_t*)dh2k) {
        pkType = DH2K;
    }
    else if (*(int32_t*)type == *(int32_t*)dh3k) {
        pkType = DH3K;
    }
    else if (*(int32_t*)type == *(int32_t*)dh4k) {
        pkType = DH4K;
    }
    else if (*(int32_t*)type == *(int32_t*)ec25) {
        pkType = EC25;
    }
    else if (*(int32_t*)type == *(int32_t*)ec38) {
        pkType = EC38;
    }
    else if (*(int32_t*)type == *(int32_t*)e255) {
        pkType = E255;
    }
    else if (*(int32_t*)type == *(int32_t*)e414) {
        pkType = E414;
    }
    else {
        return;
    }

#if defined(_WIN32) || defined(_WIN64)
    if (InterlockedCompareExchange(&dh_init_started, 1, 0) == 0) {
        InitializeCriticalSection(&dh_init_lock);
    }
    EnterCriticalSection(&dh_init_lock);
#else
    pthread_mutex_lock(&dh_init_lock);
#endif

    if (!dhinit) {
        bnP2048 = BN_bin2bn(P2048,sizeof(P2048),nullptr);
        bnP3072 = BN_bin2bn(P3072,sizeof(P3072),nullptr);
        bnP4096 = BN_bin2bn(P4096,sizeof(P4096),nullptr);

        if (bnP2048 && bnP3072 && bnP4096) {
            bnP2048MinusOne = BN_dup(bnP2048);
            if (bnP2048MinusOne) {
                BN_sub_word(bnP2048MinusOne, 1);
            }

            bnP3072MinusOne = BN_dup(bnP3072);
            if (bnP3072MinusOne) {
                BN_sub_word(bnP3072MinusOne, 1);
            }

            bnP4096MinusOne = BN_dup(bnP4096);
            if (bnP4096MinusOne) {
                BN_sub_word(bnP4096MinusOne, 1);
            }
            dhinit = 1;
        }
    }
    
#if defined(_WIN32) || defined(_WIN64)
    LeaveCriticalSection(&dh_init_lock);
#else
    pthread_mutex_unlock(&dh_init_lock);
#endif

    if (!dhinit) {
        pkType = -1;
        return;
    }

    switch (pkType) {
    case DH2K:
    case DH3K:
    case DH4K: {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        DH* tmpCtx = DH_new();
        if (tmpCtx == nullptr) {
            pkType = -1;
            return;
        }
        ctx = static_cast<void*>(tmpCtx);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        
        BIGNUM* g = BN_new();
        if (g == nullptr) {
            DH_free(tmpCtx);
            ctx = nullptr;
            pkType = -1;
            return;
        }
        BN_set_word(g, DH_GENERATOR_2);

        BIGNUM* p = nullptr;
        int priv_key_len = 0;
        
        if (pkType == DH2K) {
            p = BN_dup(bnP2048);
            priv_key_len = 32;
        }
        else if (pkType == DH3K) {
            p = BN_dup(bnP3072);
            priv_key_len = 48;
        }
        else if (pkType == DH4K) {
            p = BN_dup(bnP4096);
            priv_key_len = 64;
        }
        
        if (p == nullptr) {
            BN_free(g);
            DH_free(tmpCtx);
            ctx = nullptr;
            pkType = -1;
            return;
        }
        
        RAND_bytes(random, priv_key_len);
        BIGNUM* priv_key = BN_bin2bn(random, priv_key_len, nullptr);
        if (priv_key == nullptr) {
            BN_free(p);
            BN_free(g);
            DH_free(tmpCtx);
            ctx = nullptr;
            pkType = -1;
            return;
        }
        
        zrtp_DH_set0_pqg(tmpCtx, p, nullptr, g);
        zrtp_DH_set0_key(tmpCtx, nullptr, priv_key);
        break;
    }

    case EC25: {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        ctx = static_cast<void*>(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        if (ctx == nullptr) {
            pkType = -1;
        }
        break;
    }
    case EC38: {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        ctx = static_cast<void*>(EC_KEY_new_by_curve_name(NID_secp384r1));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        if (ctx == nullptr) {
            pkType = -1;
        }
        break;
    }
    
    case E255: {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        ctx = static_cast<void*>(EC_KEY_new_by_curve_name(NID_X25519));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        if (ctx == nullptr) {
            pkType = -1;
        }
        break;
    }
    
    case E414: {
        pkType = -1;
        break;
    }

    default:
        pkType = -1;
        break;
    }
}

ZrtpDH::~ZrtpDH() {
    if (ctx == nullptr)
        return;

    switch (pkType) {
    case DH2K:
    case DH3K:
    case DH4K:
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        DH_free(static_cast<DH*>(ctx));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        break;

    case EC25:
    case EC38:
    case E255:
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        EC_KEY_free(static_cast<EC_KEY*>(ctx));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        break;
        
    case E414:
        break;
        
    default:
        return;
    }
}

int32_t ZrtpDH::computeSecretKey(uint8_t *pubKeyBytes, uint8_t *secret) {

    if (ctx == nullptr || pkType < 0) {
        return -1;
    }

    if (pubKeyBytes == nullptr || secret == nullptr) {
        return -1;
    }

    if (pkType == DH2K || pkType == DH3K || pkType == DH4K) {
        auto* tmpCtx = static_cast<DH*>(ctx);

        int32_t dhSize = getDhSize();
        if (dhSize <= 0) {
            return -1;
        }

        BIGNUM* new_pub_key = BN_bin2bn(pubKeyBytes, dhSize, nullptr);
        if (new_pub_key == nullptr) {
            return -1;
        }
        
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        int result = DH_compute_key(secret, new_pub_key, tmpCtx);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        
        BN_free(new_pub_key);
        
        if (result < 0) {
            return -1;
        }
        
        return result;
    }
    
    if (pkType == EC25 || pkType == EC38 || pkType == E255) {
        uint8_t buffer[200];
        int32_t ret;
        int32_t len = getPubKeySize();
        
        if (len <= 0 || len+1 > static_cast<int32_t>(sizeof(buffer))) {
            return -1;
        }

        buffer[0] = POINT_CONVERSION_UNCOMPRESSED;
        memcpy(buffer+1, pubKeyBytes, len);
        
        EC_KEY* ecKey = static_cast<EC_KEY*>(ctx);
        if (ecKey == nullptr) {
            return -1;
        }
        
        EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ecKey));
        if (point == nullptr) {
            return -1;
        }
        
        if (EC_POINT_oct2point(EC_KEY_get0_group(ecKey), point, buffer, len+1, nullptr) != 1) {
            EC_POINT_free(point);
            return -1;
        }
        
        int32_t secretLen = getDhSize();
        if (secretLen <= 0) {
            EC_POINT_free(point);
            return -1;
        }
        
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        ret = ECDH_compute_key(secret, secretLen, point, ecKey, nullptr);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        EC_POINT_free(point);
        
        if (ret < 0) {
            return -1;
        }
        
        return ret;
    }
    
    if (pkType == E414) {
        return -1;
    }
    
    return -1;
}

int32_t ZrtpDH::generatePublicKey()
{
    if (ctx == nullptr || pkType < 0) {
        return 0;
    }

    if (pkType == DH2K || pkType == DH3K || pkType == DH4K) {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        int result = DH_generate_key(static_cast<DH*>(ctx));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        return result;
    }

    if (pkType == EC25 || pkType == EC38) {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        int result = EC_KEY_generate_key(static_cast<EC_KEY*>(ctx));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        return result;
    }
    return 0;
}

uint32_t ZrtpDH::getDhSize() const
{
    if (pkType < 0) {
        return 0;
    }
    
    if (pkType == DH2K || pkType == DH3K || pkType == DH4K) {
        if (ctx == nullptr) {
            return 0;
        }
        
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        return DH_size(static_cast<DH*>(ctx));
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
    }

    if (pkType == EC25)
        return 32;
    if (pkType == EC38)
        return 48;
    if (pkType == E255)
        return 32;
    if (pkType == E414)
        return 52;

    return 0;
}

int32_t ZrtpDH::getPubKeySize() const
{
    if (ctx == nullptr || pkType < 0) {
        return 0;
    }

    if (pkType == DH2K || pkType == DH3K || pkType == DH4K) {
        const BIGNUM* pub_key = zrtp_DH_get0_pub_key(static_cast<DH*>(ctx));
        if (pub_key == nullptr) {
            return 0;
        }
        return BN_num_bytes(pub_key);
    }

    if (pkType == EC25 || pkType == EC38 || pkType == E255) {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        EC_KEY* ecKey = static_cast<EC_KEY*>(ctx);
        const EC_POINT* pub_key = EC_KEY_get0_public_key(ecKey);
        if (pub_key == nullptr) {
            return 0;
        }
        
        size_t len = EC_POINT_point2oct(EC_KEY_get0_group(ecKey),
                                  pub_key,
                                  POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        
        if (len == 0) {
            return 0;
        }
        
        return static_cast<int32_t>(len - 1);
    }
    
    if (pkType == E414) {
        return 52;
    }
    
    return 0;

}

int32_t ZrtpDH::getPubKeyBytes(uint8_t *buf) const
{
    if (ctx == nullptr || pkType < 0 || buf == nullptr) {
        return 0;
    }

    if (pkType == DH2K || pkType == DH3K || pkType == DH4K) {
        int32_t pubKeySize = getPubKeySize();
        if (pubKeySize <= 0) {
            return 0;
        }
        
        int32_t dhSize = getDhSize();
        int32_t prepend = dhSize - pubKeySize;
        if (prepend > 0) {
            memset(buf, 0, prepend);
        }
        const BIGNUM* pub_key = zrtp_DH_get0_pub_key(static_cast<DH*>(ctx));
        if (pub_key == nullptr) {
            return 0;
        }
        return BN_bn2bin(pub_key, buf + prepend);
    }
    
    if (pkType == EC25 || pkType == EC38 || pkType == E255) {
        uint8_t buffer[200];

        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        EC_KEY* ecKey = static_cast<EC_KEY*>(ctx);
        const EC_POINT* pub_key = EC_KEY_get0_public_key(ecKey);
        if (pub_key == nullptr) {
            return 0;
        }
        
        size_t len = EC_POINT_point2oct(EC_KEY_get0_group(ecKey),
                                     pub_key,
                                     POINT_CONVERSION_UNCOMPRESSED, buffer, sizeof(buffer), nullptr);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        
        if (len <= 1) {
            return 0;
        }
        
        memcpy(buf, buffer+1, len-1);
        return static_cast<int32_t>(len-1);
    }
    
    if (pkType == E414) {
        return 0;
    }
    
    return 0;
}

int32_t ZrtpDH::checkPubKey(uint8_t *pubKeyBytes) const
{
    if (ctx == nullptr || pkType < 0 || pubKeyBytes == nullptr) {
        return 0;
    }

    if (pkType == EC25 || pkType == EC38) {
        uint8_t buffer[200];
        int32_t ret;
        int32_t len = getPubKeySize();

        if (len <= 0 || len+1 > static_cast<int32_t>(sizeof(buffer))) {
            return 0;
        }
        buffer[0] = POINT_CONVERSION_UNCOMPRESSED;
        memcpy(buffer+1, pubKeyBytes, len);

        EC_KEY* ecKey = static_cast<EC_KEY*>(ctx);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(ecKey));
        if (point == nullptr) {
            return 0;
        }
        
        if (EC_POINT_oct2point(EC_KEY_get0_group(ecKey), point, buffer, len+1, nullptr) != 1) {
            EC_POINT_free(point);
            return 0;
        }
        
        EC_KEY* chkKey = EC_KEY_new();
        if (chkKey == nullptr) {
            EC_POINT_free(point);
            return 0;
        }
        
        if (EC_KEY_set_group(chkKey, EC_KEY_get0_group(ecKey)) != 1 ||
            EC_KEY_set_public_key(chkKey, point) != 1) {
            EC_KEY_free(chkKey);
            EC_POINT_free(point);
            return 0;
        }
        
        ret = EC_KEY_check_key(chkKey);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif

        EC_POINT_free(point);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        EC_KEY_free(chkKey);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
        
        return ret;
    }

    int32_t dhSize = getDhSize();
    if (dhSize <= 0) {
        return 0;
    }

    BIGNUM* pubKeyOther = BN_bin2bn(pubKeyBytes, dhSize, nullptr);
    if (pubKeyOther == nullptr) {
        return 0;
    }

    int result = 1;
    
    if (pkType == DH2K) {
        if (BN_cmp(bnP2048MinusOne, pubKeyOther) == 0)
            result = 0;
    }
    else if (pkType == DH3K) {
        if (BN_cmp(bnP3072MinusOne, pubKeyOther) == 0)
            result = 0;
    }
    else if (pkType == DH4K) {
        if (BN_cmp(bnP4096MinusOne, pubKeyOther) == 0)
            result = 0;
    }
    else {
        result = 0;
    }
    
    if (result && BN_is_one(pubKeyOther)) {
        result = 0;
    }

    BN_free(pubKeyOther);
    return result;
}

const char* ZrtpDH::getDHtype()
{
    switch (pkType) {
    case DH2K:
        return dh2k;
    case DH3K:
        return dh3k;
    case DH4K:
        return dh4k;
    case EC25:
        return ec25;
    case EC38:
        return ec38;
    case E255:
        return e255;
    case E414:
        return e414;
    default:
        return nullptr;
    }
}

/** EMACS **
 * Local variables:
 * mode: c++
 * c-default-style: ellemtel
 * c-basic-offset: 4
 * End:
 */
