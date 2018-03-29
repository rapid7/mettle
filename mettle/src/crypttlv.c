#include "crypttlv.h"

int generate_aes_key(unsigned char *aes_key)
{
#ifndef __MINGW32__
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    char *pers = "meterpreter mettle seed";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if ((mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                               (unsigned char *) pers, strlen(pers))) != 0)
    {
        if ((mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, 32)) != 0)
        {
            return -1;
        }
    }
    return 0;
#else
    return -1;
#endif
}

size_t aes_decrypt(unsigned char* key, const unsigned char* data, char* result, size_t data_len)
{
    return -1;
}

size_t aes_encrypt(unsigned char* key, const unsigned char* data, char* result, size_t data_len)
{
   return -1;
}

size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, const unsigned char* data, size_t data_len, char* result)
{
#ifndef __MINGW32__
    mbedtls_pk_context pk;

    if (pkey_len > 0) {
        mbedtls_pk_init(&pk);
        if (mbedtls_pk_parse_public_key(&pk, pkey, pkey_len) != 0)
        {
            return -1;
        }
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
        size_t olen = 0;

        if((mbedtls_pk_encrypt(&pk, data, data_len,
                               buf, &olen, sizeof(buf),
                               mbedtls_ctr_drbg_random, &result)) != 0)
        {
            return -1;
        }
        // malloc and result on the heap? or are we avoiding allocating memory to free later?
        return olen;
    }
#endif
    return -1;
}
