#ifndef __MINGW32__

#include <stdlib.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

#include <string.h>

#else

#include <stddef.h>

#endif
#include "tlv.h"

#define ENC_NONE 0
#define ENC_AES256 1
#define AES_KEY_LEN 32
#define AES_IV "zrgrecergre vavg" // 'meterpreter init' rot13 :-)


/**
 * Generate an encryption key for the enc_flag type requested
 */
struct tlv_encryption_ctx* create_tlv_context(unsigned int enc_flag);

void free_tlv_encryption_ctx(struct tlv_encryption_ctx *ctx);

/**
 * decrypt data with TLV data with on context passed
 * returns 0 on success
 */
size_t decrypt_tlv(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result);

/**
 * encrypt data with TLV data with on context passed
 * returns 0 on success
 */
size_t encrypt_tlv(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result);

/**
 * Accepts a string rsa private and a value to encrypt into the result buffer
 */
size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, const unsigned char* data, size_t data_len, unsigned char* result);
