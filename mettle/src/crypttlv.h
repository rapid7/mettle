#ifndef __MINGW32__

#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

#include <string.h>

#else

#include <stddef.h>

#endif

/**
 * Generate a 32 byte AES key
 */
int generate_aes_key(unsigned char *aes_key);

/**
 * decrypt data with AES key
 */
size_t aes_decrypt(unsigned char* key, const unsigned char* data, char* result, size_t data_len);

/**
 * encrypt data with AES key
 */
size_t aes_encrypt(unsigned char* key, const unsigned char* data, char* result, size_t data_len);

/**
 * Accept a string rsa private and a value to encrypt into the result buffer
 */
size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, const unsigned char* data, size_t data_len, char* result);
