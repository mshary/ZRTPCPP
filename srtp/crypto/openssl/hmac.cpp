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

/*
 * Authors: Werner Dittmann
 */

#include <cstdint>
#include <openssl/hmac.h>
#include <srtp/crypto/hmac.h>
#include <vector>
#include "../../../zrtp/crypto/openssl/openssl_compat.h"

void hmac_sha1(const uint8_t* key, int64_t keyLength,
               const uint8_t* data, uint64_t dataLength,
               uint8_t* mac, int32_t* macLength)
{
    HMAC(EVP_sha1(), key, static_cast<int>(keyLength),
         data, dataLength, mac,
         reinterpret_cast<uint32_t*>(macLength));
}

void hmac_sha1(const uint8_t* key, uint64_t keyLength,
                const std::vector<const uint8_t*>& data,
                const std::vector<uint64_t>& dataLength,
                uint8_t* mac, int32_t* macLength) {
    hmac_ctx_t ctx = hmac_ctx_new();
    if (!ctx) return;
    
    hmac_init_ex(ctx, key, static_cast<int>(keyLength), EVP_sha1());
    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmac_update(ctx, data[i], dataLength[i]);
    }
    hmac_final(ctx, mac, reinterpret_cast<uint32_t*>(macLength));
    hmac_ctx_free(ctx);
}

void* createSha1HmacContext(const uint8_t* key, uint64_t keyLength)
{
    hmac_ctx_t ctx = hmac_ctx_new();
    if (!ctx) return nullptr;
    
    hmac_init_ex(ctx, key, static_cast<int>(keyLength), EVP_sha1());
    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, uint64_t keyLength)
{
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;
    
#if defined(OPENSSL_1_0_API)
    hmac_ctx_init(pctx);
#endif
    hmac_init_ex(pctx, key, static_cast<int>(keyLength), EVP_sha1());
    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint64_t data_length,
                  uint8_t* mac, int32_t* mac_length)
{
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;

    hmac_init_ex(pctx, nullptr, 0, nullptr);
    hmac_update(pctx, data, data_length );
    hmac_final(pctx, mac, reinterpret_cast<uint32_t*>(mac_length) );
}

void hmacSha1Ctx(void* ctx,
                  const std::vector<const uint8_t*>& data,
                  const std::vector<uint64_t>& dataLength,
                  uint8_t* mac, uint32_t* macLength)
{
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;

    hmac_init_ex(pctx, nullptr, 0, nullptr);
    for (size_t i = 0, size = data.size(); i < size; i++) {
        hmac_update(pctx, data[i], dataLength[i]);
    }
    hmac_final(pctx, mac, reinterpret_cast<uint32_t*>(macLength) );
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
        hmac_ctx_free((hmac_ctx_t)ctx);
    }
}
