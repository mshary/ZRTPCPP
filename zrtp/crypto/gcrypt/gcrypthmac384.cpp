#include <gcrypt.h>
#include <crypto/hmac384.h>

void hmac_sha384(uint8_t* key, uint32_t keyLength,
        uint8_t* data, int32_t dataLength,
                uint8_t* mac, uint32_t* macLength)
{
    if (key == nullptr || data == nullptr || mac == nullptr) {
        if (macLength != nullptr) {
            *macLength = 0;
        }
        return;
    }
    
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA384, GCRY_MD_FLAG_HMAC);
    if (err) {
        if (macLength != nullptr) {
            *macLength = 0;
        }
        return;
    }
    
    err = gcry_md_setkey(hd, key, keyLength);
    if (err) {
        gcry_md_close(hd);
        if (macLength != nullptr) {
            *macLength = 0;
        }
        return;
    }

    gcry_md_write (hd, data, dataLength);

    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA384);
    if (p != nullptr) {
        memcpy(mac, p, SHA384_DIGEST_LENGTH);
    }
    if (macLength != NULL) {
        *macLength = SHA384_DIGEST_LENGTH;
    }
    gcry_md_close (hd);
}

void hmac_sha384( uint8_t* key, uint32_t keyLength,
                  uint8_t* dataChunks[],
                  uint32_t dataChunkLength[],
                  uint8_t* mac, uint32_t* macLength )
{
    if (key == nullptr || dataChunks == nullptr || mac == nullptr) {
        if (macLength != nullptr) {
            *macLength = 0;
        }
        return;
    }
    
    gcry_md_hd_t hd;
    gcry_error_t err = 0;

    err = gcry_md_open(&hd, GCRY_MD_SHA384, GCRY_MD_FLAG_HMAC);
    if (err) {
        if (macLength != nullptr) {
            *macLength = 0;
        }
        return;
    }
    
    err = gcry_md_setkey(hd, key, keyLength);
    if (err) {
        gcry_md_close(hd);
        if (macLength != nullptr) {
            *macLength = 0;
        }
        return;
    }

    while (*dataChunks) {
        if (*dataChunkLength > 0) {
            gcry_md_write (hd, *dataChunks, (uint32_t)(*dataChunkLength));
        }
    dataChunks++;
    dataChunkLength++;
    }
    uint8_t* p = gcry_md_read (hd, GCRY_MD_SHA384);
    if (p != nullptr) {
        memcpy(mac, p, SHA384_DIGEST_LENGTH);
    }
    if (macLength != NULL) {
        *macLength = SHA384_DIGEST_LENGTH;
    }
    gcry_md_close (hd);
}