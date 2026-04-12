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
    if (key == nullptr || data == nullptr || mac == nullptr || macLength == nullptr) {
        return;
    }
    
    unsigned int tmp;
    HMAC(EVP_sha1(), key, static_cast<int>(keyLength),
         data, dataLength, mac, &tmp);
    *macLength = static_cast<int32_t>(tmp);
}

void hmac_sha1(const uint8_t* key, uint64_t keyLength,
                const std::vector<const uint8_t*>& data,
                const std::vector<uint64_t>& dataLength,
                uint8_t* mac, int32_t* macLength) {
    if (key == nullptr || mac == nullptr || macLength == nullptr) {
        return;
    }
    
    hmac_ctx_t ctx = hmac_ctx_new();
    if (!ctx) {
        *macLength = 0;
        return;
    }
    
    if (!hmac_init_ex(ctx, key, static_cast<int>(keyLength), EVP_sha1())) {
        hmac_ctx_free(ctx);
        *macLength = 0;
        return;
    }
    
    for (size_t i = 0, size = data.size(); i < size; i++) {
        if (data[i] == nullptr || dataLength[i] == 0) {
            continue;
        }
        if (!hmac_update(ctx, data[i], dataLength[i])) {
            hmac_ctx_free(ctx);
            *macLength = 0;
            return;
        }
    }
    
    unsigned int tmp;
    if (!hmac_final(ctx, mac, &tmp)) {
        hmac_ctx_free(ctx);
        *macLength = 0;
        return;
    }
    
    *macLength = static_cast<int32_t>(tmp);
    hmac_ctx_free(ctx);
}

void* createSha1HmacContext(const uint8_t* key, uint64_t keyLength)
{
    if (key == nullptr) {
        return nullptr;
    }
    
    hmac_ctx_t ctx = hmac_ctx_new();
    if (!ctx) {
        return nullptr;
    }
    
    if (!hmac_init_ex(ctx, key, static_cast<int>(keyLength), EVP_sha1())) {
        hmac_ctx_free(ctx);
        return nullptr;
    }
    
    return ctx;
}

void* initializeSha1HmacContext(void* ctx, uint8_t* key, uint64_t keyLength)
{
    if (ctx == nullptr || key == nullptr) {
        return nullptr;
    }
    
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;
    
#if defined(OPENSSL_1_0_API)
    hmac_ctx_init(pctx);
#endif
    
    if (!hmac_init_ex(pctx, key, static_cast<int>(keyLength), EVP_sha1())) {
        return nullptr;
    }
    
    return pctx;
}

void hmacSha1Ctx(void* ctx, const uint8_t* data, uint64_t data_length,
                  uint8_t* mac, int32_t* mac_length)
{
    if (ctx == nullptr || data == nullptr || mac == nullptr || mac_length == nullptr) {
        return;
    }
    
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;

    if (!hmac_init_ex(pctx, nullptr, 0, nullptr)) {
        *mac_length = 0;
        return;
    }
    
    if (!hmac_update(pctx, data, data_length )) {
        *mac_length = 0;
        return;
    }
    
    unsigned int tmp;
    if (!hmac_final(pctx, mac, &tmp)) {
        *mac_length = 0;
        return;
    }
    
    *mac_length = static_cast<int32_t>(tmp);
}

void hmacSha1Ctx(void* ctx,
                  const std::vector<const uint8_t*>& data,
                  const std::vector<uint64_t>& dataLength,
                  uint8_t* mac, uint32_t* macLength)
{
    if (ctx == nullptr || mac == nullptr || macLength == nullptr) {
        return;
    }
    
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;

    if (!hmac_init_ex(pctx, nullptr, 0, nullptr)) {
        *macLength = 0;
        return;
    }
    
    for (size_t i = 0, size = data.size(); i < size; i++) {
        if (data[i] == nullptr || dataLength[i] == 0) {
            continue;
        }
        if (!hmac_update(pctx, data[i], dataLength[i])) {
            *macLength = 0;
            return;
        }
    }
    
    if (!hmac_final(pctx, mac, macLength)) {
        *macLength = 0;
        return;
    }
}

void freeSha1HmacContext(void* ctx)
{
    if (ctx) {
        hmac_ctx_free((hmac_ctx_t)ctx);
    }
}
