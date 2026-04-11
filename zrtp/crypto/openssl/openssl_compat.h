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
#if defined(OPENSSL_3_API) || defined(OPENSSL_1_1_API)
/* OpenSSL 1.1.x and 3.x use opaque HMAC_CTX */
typedef HMAC_CTX* hmac_ctx_t;

static inline hmac_ctx_t hmac_ctx_new(void) {
    return HMAC_CTX_new();
}

static inline void hmac_ctx_free(hmac_ctx_t ctx) {
    HMAC_CTX_free(ctx);
}

static inline void hmac_ctx_init(hmac_ctx_t ctx) {
    /* No-op for 1.1.x and 3.x, allocation does initialization */
}

static inline void hmac_ctx_cleanup(hmac_ctx_t ctx) {
    /* No-op for 1.1.x and 3.x, use HMAC_CTX_free instead */
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
    DH_get0_key(dh, pub_key, priv_key);
#else
    /* OpenSSL 1.1.x */
    *pub_key = DH_get0_pub_key(dh);
    *priv_key = DH_get0_priv_key(dh);
#endif
}

static inline void zrtp_DH_get0_pqg(const DH* dh, const BIGNUM** p, const BIGNUM** q, const BIGNUM** g) {
#if defined(OPENSSL_3_API)
    DH_get0_pqg(dh, p, q, g);
#else
    /* OpenSSL 1.1.x */
    *p = DH_get0_p(dh);
    *q = DH_get0_q(dh);
    *g = DH_get0_g(dh);
#endif
}

static inline int zrtp_DH_set0_key(DH* dh, BIGNUM* pub_key, BIGNUM* priv_key) {
#if defined(OPENSSL_3_API)
    return DH_set0_key(dh, pub_key, priv_key);
#else
    /* OpenSSL 1.1.x */
    DH_set0_key(dh, pub_key, priv_key);
    return 1;
#endif
}

static inline int zrtp_DH_set0_pqg(DH* dh, BIGNUM* p, BIGNUM* q, BIGNUM* g) {
#if defined(OPENSSL_3_API)
    return DH_set0_pqg(dh, p, q, g);
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
    DH_get0_key(dh, &pub_key, NULL);
    return pub_key;
}

/* Helper function to get DH private key as BIGNUM */
static inline const BIGNUM* DH_get0_priv_key_compat(const DH* dh) {
    const BIGNUM* priv_key;
    DH_get0_key(dh, NULL, &priv_key);
    return priv_key;
}

/* Helper function to get DH p parameter as BIGNUM */
static inline const BIGNUM* DH_get0_p_compat(const DH* dh) {
    const BIGNUM* p;
    DH_get0_pqg(dh, &p, NULL, NULL);
    return p;
}

/* Helper function to get DH g parameter as BIGNUM */
static inline const BIGNUM* DH_get0_g_compat(const DH* dh) {
    const BIGNUM* g;
    DH_get0_pqg(dh, NULL, NULL, &g);
    return g;
}

#endif /* OPENSSL_COMPAT_H */