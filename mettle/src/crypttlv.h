#ifndef __MINGW32__

#include <stdlib.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls_ext.h"
#include <string.h>

#else

#include <stddef.h>

#endif
#include "tlv.h"

#define ENC_NONE 0
#define ENC_AES256 1
#define AES_KEY_LEN 32
#define AES_IV_LEN 16


/**
 * Generate an encryption key for the enc_flag type requested
 */
struct tlv_encryption_ctx* create_tlv_encryption_context(unsigned int enc_flag);

void free_tlv_encryption_ctx(struct tlv_encryption_ctx *ctx);

/**
 * decrypt TLV data with the context passed
 * returns a pointer to the decrypted data with same
 * provided in the tlv_header len as provided in the tlv header
 */
void * decrypt_tlv(struct tlv_encryption_ctx* ctx, void *p, size_t buf_len);

/**
 * encrypt data with TLV data with the context passed
 * returns a pointer to a new buffer containing a new tlv_header, iv and
 * encrypted data offset TLV_PREPEND_LEN - TLV_MIN_LEN
 */
void * encrypt_tlv(struct tlv_encryption_ctx* ctx, void *p, size_t buf_len);

/**
 * Accepts a string rsa private and a value to encrypt into the result buffer
 */
size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, struct tlv_encryption_ctx *ctx, unsigned char* result);
