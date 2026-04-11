/*
 * OpenSSL compatibility layer for ZRTPCPP
 * 
 * This header provides compatibility between OpenSSL 1.0.x/1.1.x and OpenSSL 3.x
 * Copyright 2026
 */

#ifndef OPENSSL_COMPAT_H
#define OPENSSL_COMPAT_H

#include <openssl/opensslv.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <cstring>

/* OpenSSL version detection */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* OpenSSL 1.0.x */
#define OPENSSL_1_0_API 1
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
/* OpenSSL 1.1.x */
#define OPENSSL_1_1_API 1
#else
/* OpenSSL 3.x */
#define OPENSSL_3_API 1
#endif

/* HMAC_CTX compatibility */
#if defined(OPENSSL_3_API)
/* OpenSSL 3.x - use EVP_MAC API */
#include <openssl/evp.h>
#include <openssl/core_names.h>

typedef struct {
    EVP_MAC_CTX* evp_mac_ctx;
    const EVP_MD* md;
} hmac_ctx_struct;

typedef hmac_ctx_struct* hmac_ctx_t;

static inline hmac_ctx_t hmac_ctx_new(void) {
    hmac_ctx_struct* ctx = (hmac_ctx_struct*)calloc(1, sizeof(hmac_ctx_struct));
    if (!ctx) return nullptr;
    
    ctx->evp_mac_ctx = EVP_MAC_CTX_new(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!ctx->evp_mac_ctx) {
        free(ctx);
        return nullptr;
    }
    return ctx;
}

static inline void hmac_ctx_free(hmac_ctx_t ctx) {
    if (ctx) {
        if (ctx->evp_mac_ctx) {
            EVP_MAC_CTX_free(ctx->evp_mac_ctx);
        }
        free(ctx);
    }
}

static inline void hmac_ctx_init(hmac_ctx_t ctx) {
    /* No-op for EVP_MAC API */
}

static inline void hmac_ctx_cleanup(hmac_ctx_t ctx) {
    /* No-op for EVP_MAC API, use hmac_ctx_free instead */
}

#elif defined(OPENSSL_1_1_API)
/* OpenSSL 1.1.x use opaque HMAC_CTX */
typedef HMAC_CTX* hmac_ctx_t;

static inline hmac_ctx_t hmac_ctx_new(void) {
    return HMAC_CTX_new();
}

static inline void hmac_ctx_free(hmac_ctx_t ctx) {
    HMAC_CTX_free(ctx);
}

static inline void hmac_ctx_init(hmac_ctx_t ctx) {
    /* No-op for 1.1.x, allocation does initialization */
}

static inline void hmac_ctx_cleanup(hmac_ctx_t ctx) {
    /* No-op for 1.1.x, use HMAC_CTX_free instead */
}

#else
/* OpenSSL 1.0.x */
typedef HMAC_CTX hmac_ctx_t;

static inline hmac_ctx_t* hmac_ctx_new(void) {
    HMAC_CTX* ctx = (HMAC_CTX*)malloc(sizeof(HMAC_CTX));
    if (ctx) {
        HMAC_CTX_init(ctx);
    }
    return ctx;
}

static inline void hmac_ctx_free(hmac_ctx_t* ctx) {
    if (ctx) {
        HMAC_CTX_cleanup(ctx);
        free(ctx);
    }
}

static inline void hmac_ctx_init(hmac_ctx_t* ctx) {
    HMAC_CTX_init(ctx);
}

static inline void hmac_ctx_cleanup(hmac_ctx_t* ctx) {
    HMAC_CTX_cleanup(ctx);
}
#endif

/* HMAC operation compatibility functions */
#if defined(OPENSSL_3_API)
/* OpenSSL 3.x EVP_MAC API */
static inline int hmac_init_ex(hmac_ctx_t ctx, const uint8_t* key, int key_len, const EVP_MD* md) {
    if (!ctx || !ctx->evp_mac_ctx) return 0;
    
    if (md) {
        ctx->md = md;
    }
    
    if (key) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                     (char*)EVP_MD_get0_name(ctx->md), 0);
        params[1] = OSSL_PARAM_construct_end();
        
        return EVP_MAC_init(ctx->evp_mac_ctx, key, key_len, params);
    } else {
        // Re-initialize with same parameters
        return EVP_MAC_init(ctx->evp_mac_ctx, nullptr, 0, nullptr);
    }
}

static inline int hmac_update(hmac_ctx_t ctx, const uint8_t* data, size_t data_len) {
    if (!ctx || !ctx->evp_mac_ctx) return 0;
    return EVP_MAC_update(ctx->evp_mac_ctx, data, data_len);
}

static inline int hmac_final(hmac_ctx_t ctx, uint8_t* md, unsigned int* md_len) {
    if (!ctx || !ctx->evp_mac_ctx) return 0;
    
    size_t out_len = EVP_MAC_CTX_get_mac_size(ctx->evp_mac_ctx);
    int ret = EVP_MAC_final(ctx->evp_mac_ctx, md, &out_len, out_len);
    if (ret && md_len) {
        *md_len = (unsigned int)out_len;
    }
    return ret;
}

#else
/* OpenSSL 1.0.x and 1.1.x - use HMAC API */
static inline int hmac_init_ex(hmac_ctx_t ctx, const uint8_t* key, int key_len, const EVP_MD* md) {
#if defined(OPENSSL_1_1_API)
    return HMAC_Init_ex(ctx, key, key_len, md, nullptr);
#else
    HMAC_Init_ex(ctx, key, key_len, md, nullptr);
    return 1;
#endif
}

static inline int hmac_update(hmac_ctx_t ctx, const uint8_t* data, size_t data_len) {
    HMAC_Update(ctx, data, data_len);
    return 1;
}

static inline int hmac_final(hmac_ctx_t ctx, uint8_t* md, unsigned int* md_len) {
    HMAC_Final(ctx, md, md_len);
    return 1;
}
#endif

/* Threading API compatibility */
#if defined(OPENSSL_3_API)
/* OpenSSL 3.x - threading is handled automatically, no callbacks needed */
#define OPENSSL_THREADING_AUTO 1
#elif defined(OPENSSL_1_1_API)
/* OpenSSL 1.1.x - threading is automatic since 1.1.0 */
#define OPENSSL_THREADING_AUTO 1
#else
/* OpenSSL 1.0.x - needs manual threading setup */
#define OPENSSL_THREADING_MANUAL 1
#endif

/* DH structure access compatibility */
#if defined(OPENSSL_3_API) || defined(OPENSSL_1_1_API)
/* OpenSSL 1.1.x and 3.x have opaque DH structures */
/* Use different names to avoid conflicts with OpenSSL 3.x deprecated functions */
static inline void zrtp_DH_get0_key(const DH* dh, const BIGNUM** pub_key, const BIGNUM** priv_key) {
#if defined(OPENSSL_3_API)
    /* In OpenSSL 3.x, these functions exist but are deprecated */
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    DH_get0_key(dh, pub_key, priv_key);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
#else
    /* OpenSSL 1.1.x */
    *pub_key = DH_get0_pub_key(dh);
    *priv_key = DH_get0_priv_key(dh);
#endif
}

static inline void zrtp_DH_get0_pqg(const DH* dh, const BIGNUM** p, const BIGNUM** q, const BIGNUM** g) {
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    DH_get0_pqg(dh, p, q, g);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
#else
    /* OpenSSL 1.1.x */
    *p = DH_get0_p(dh);
    *q = DH_get0_q(dh);
    *g = DH_get0_g(dh);
#endif
}

static inline int zrtp_DH_set0_key(DH* dh, BIGNUM* pub_key, BIGNUM* priv_key) {
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    int ret = DH_set0_key(dh, pub_key, priv_key);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
    return ret;
#else
    /* OpenSSL 1.1.x */
    DH_set0_key(dh, pub_key, priv_key);
    return 1;
#endif
}

static inline int zrtp_DH_set0_pqg(DH* dh, BIGNUM* p, BIGNUM* q, BIGNUM* g) {
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    int ret = DH_set0_pqg(dh, p, q, g);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
    return ret;
#else
    /* OpenSSL 1.1.x */
    DH_set0_pqg(dh, p, q, g);
    return 1;
#endif
}

#else
/* OpenSSL 1.0.x - direct structure access */
static inline void zrtp_DH_get0_key(const DH* dh, const BIGNUM** pub_key, const BIGNUM** priv_key) {
    *pub_key = dh->pub_key;
    *priv_key = dh->priv_key;
}

static inline void zrtp_DH_get0_pqg(const DH* dh, const BIGNUM** p, const BIGNUM** q, const BIGNUM** g) {
    *p = dh->p;
    *q = dh->q;
    *g = dh->g;
}

static inline int zrtp_DH_set0_key(DH* dh, BIGNUM* pub_key, BIGNUM* priv_key) {
    dh->pub_key = pub_key;
    dh->priv_key = priv_key;
    return 1;
}

static inline int zrtp_DH_set0_pqg(DH* dh, BIGNUM* p, BIGNUM* q, BIGNUM* g) {
    dh->p = p;
    dh->q = q;
    dh->g = g;
    return 1;
}
#endif

/* Helper function to get DH public key as BIGNUM */
static inline const BIGNUM* zrtp_DH_get0_pub_key(const DH* dh) {
    const BIGNUM* pub_key;
    zrtp_DH_get0_key(dh, &pub_key, NULL);
    return pub_key;
}

/* Helper function to get DH private key as BIGNUM */
static inline const BIGNUM* zrtp_DH_get0_priv_key(const DH* dh) {
    const BIGNUM* priv_key;
    zrtp_DH_get0_key(dh, NULL, &priv_key);
    return priv_key;
}

/* Helper function to get DH p parameter as BIGNUM */
static inline const BIGNUM* zrtp_DH_get0_p(const DH* dh) {
    const BIGNUM* p;
    zrtp_DH_get0_pqg(dh, &p, NULL, NULL);
    return p;
}

/* Helper function to get DH g parameter as BIGNUM */
static inline const BIGNUM* zrtp_DH_get0_g(const DH* dh) {
    const BIGNUM* g;
    zrtp_DH_get0_pqg(dh, NULL, NULL, &g);
    return g;
}

/* Helper function to get DH public key as BIGNUM */
static inline const BIGNUM* DH_get0_pub_key_compat(const DH* dh) {
    const BIGNUM* pub_key;
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    DH_get0_key(dh, &pub_key, NULL);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
#else
    DH_get0_key(dh, &pub_key, NULL);
#endif
    return pub_key;
}

/* Helper function to get DH private key as BIGNUM */
static inline const BIGNUM* DH_get0_priv_key_compat(const DH* dh) {
    const BIGNUM* priv_key;
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    DH_get0_key(dh, NULL, &priv_key);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
#else
    DH_get0_key(dh, NULL, &priv_key);
#endif
    return priv_key;
}

/* Helper function to get DH p parameter as BIGNUM */
static inline const BIGNUM* DH_get0_p_compat(const DH* dh) {
    const BIGNUM* p;
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    DH_get0_pqg(dh, &p, NULL, NULL);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
#else
    DH_get0_pqg(dh, &p, NULL, NULL);
#endif
    return p;
}

/* Helper function to get DH g parameter as BIGNUM */
static inline const BIGNUM* DH_get0_g_compat(const DH* dh) {
    const BIGNUM* g;
#if defined(OPENSSL_3_API)
    /* Suppress deprecation warnings for OpenSSL 3.x compatibility */
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    DH_get0_pqg(dh, NULL, NULL, &g);
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #endif
#else
    DH_get0_pqg(dh, NULL, NULL, &g);
#endif
    return g;
}

#endif /* OPENSSL_COMPAT_H */