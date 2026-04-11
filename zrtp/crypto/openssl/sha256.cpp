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

#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <crypto/sha256.h>

void sha256(const uint8_t *data, uint64_t data_length, uint8_t *digest)
{
	SHA256(data, data_length, digest);
}

void sha256(const std::vector<const uint8_t*>& data, const std::vector<uint64_t >& dataLength, uint8_t *digest)
{
	SHA256_CTX ctx = {};
	#if defined(OPENSSL_3_API) && defined(__GNUC__)
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	#endif
	SHA256_Init( &ctx);
    for (size_t i = 0, size = data.size(); i < size; i++) {
        SHA256_Update(&ctx, data[i], dataLength[i]);
    }
	SHA256_Final(digest, &ctx);
	#if defined(OPENSSL_3_API) && defined(__GNUC__)
	#pragma GCC diagnostic pop
	#endif
}

void* createSha256Context()
{
    auto* ctx = (SHA256_CTX*)malloc(sizeof (SHA256_CTX));
    if (ctx == nullptr)
        return nullptr;
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    SHA256_Init(ctx);
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic pop
    #endif
    return (void*)ctx;
}

void closeSha256Context(void* ctx, uint8_t * digest)
{
    auto* hd = (SHA256_CTX*)ctx;

    if (digest != nullptr && hd != nullptr) {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        SHA256_Final(digest, hd);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
    }
    free(hd);
}

void* initializeSha256Context(void* ctx) 
{
    auto* hd = (SHA256_CTX*)ctx;
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    SHA256_Init(hd);
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic pop
    #endif
    return (void*)hd;
}

void finalizeSha256Context(void* ctx, uint8_t * digest)
{
    auto* hd = (SHA256_CTX*)ctx;
    if (digest != nullptr && hd != nullptr) {
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        #endif
        SHA256_Final(digest, hd);
        #if defined(OPENSSL_3_API) && defined(__GNUC__)
        #pragma GCC diagnostic pop
        #endif
    }
}

void sha256Ctx(void* ctx, const uint8_t* data, uint64_t dataLength)
{
    auto* hd = (SHA256_CTX*)ctx;
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    SHA256_Update(hd, data, dataLength);
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic pop
    #endif
}

void sha256Ctx(void* ctx, const std::vector<const uint8_t*>& data, const std::vector<uint64_t>& dataLength)
{
    auto* hd = (SHA256_CTX*)ctx;

    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #endif
    for (size_t i = 0, size = data.size(); i < size; i++) {
        SHA256_Update(hd, data[i], dataLength[i]);
    }
    #if defined(OPENSSL_3_API) && defined(__GNUC__)
    #pragma GCC diagnostic pop
    #endif
}
