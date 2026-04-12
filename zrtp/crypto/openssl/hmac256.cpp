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

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <crypto/hmac256.h>
#include "openssl_compat.h"
#include <vector>

void hmac_sha256(const uint8_t* key, uint64_t key_length,
                 const uint8_t* data, uint64_t data_length,
                 uint8_t* mac, uint32_t* mac_length )
{
    if (key == nullptr || data == nullptr || mac == nullptr || mac_length == nullptr) {
        return;
    }
    
    unsigned int tmp;
    HMAC(EVP_sha256(), key, static_cast<int>(key_length), data, data_length, mac, &tmp);
    *mac_length = tmp;
}

void hmacSha256(const uint8_t* key, uint64_t key_length,
                const std::vector<const uint8_t*>& data,
                const std::vector<uint64_t>& dataLength,
                uint8_t* mac, uint32_t* mac_length)
{
    if (key == nullptr || mac == nullptr || mac_length == nullptr) {
        return;
    }
    
    unsigned int tmp = 0;
    hmac_ctx_t ctx = hmac_ctx_new();
    if (!ctx) {
        *mac_length = 0;
        return;
    }
    
    if (!hmac_init_ex(ctx, key, static_cast<int>(key_length), EVP_sha256())) {
        hmac_ctx_free(ctx);
        *mac_length = 0;
        return;
    }
    
    for (size_t i = 0, size = data.size(); i < size; i++) {
        if (data[i] == nullptr || dataLength[i] == 0) {
            continue;
        }
        if (!hmac_update(ctx, data[i], dataLength[i])) {
            hmac_ctx_free(ctx);
            *mac_length = 0;
            return;
        }
    }
    
    if (!hmac_final(ctx, mac, &tmp)) {
        hmac_ctx_free(ctx);
        *mac_length = 0;
        return;
    }
    
    *mac_length = tmp;
    hmac_ctx_free(ctx);
}

void* createSha256HmacContext(uint8_t* key, uint64_t keyLength)
{
    if (key == nullptr) {
        return nullptr;
    }
    
    hmac_ctx_t ctx = hmac_ctx_new();
    if (!ctx) {
        return nullptr;
    }
    
    if (!hmac_init_ex(ctx, key, static_cast<int>(keyLength), EVP_sha256())) {
        hmac_ctx_free(ctx);
        return nullptr;
    }
    
    return ctx;
}

void hmacSha256Ctx(void* ctx, const uint8_t* data, uint64_t dataLength,
                   uint8_t* mac, uint32_t* macLength)
{
    if (ctx == nullptr || data == nullptr || mac == nullptr || macLength == nullptr) {
        return;
    }
    
    hmac_ctx_t pctx = (hmac_ctx_t)ctx;

    if (!hmac_init_ex(pctx, nullptr, 0, nullptr)) {
        *macLength = 0;
        return;
    }
    
    if (!hmac_update(pctx, data, dataLength)) {
        *macLength = 0;
        return;
    }
    
    if (!hmac_final(pctx, mac, macLength)) {
        *macLength = 0;
        return;
    }
}

void hmacSha256Ctx(void* ctx,
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

void freeSha256HmacContext(void* ctx)
{
    if (ctx) {
        hmac_ctx_free((hmac_ctx_t)ctx);
    }
}
