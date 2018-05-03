#include "crypttlv.h"

size_t aes_decrypt(unsigned char* key, const unsigned char* data, size_t data_len, unsigned char* result)
{
#ifndef __MINGW32__
	unsigned char iv[16];
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	mbedtls_aes_setkey_enc( &aes, key, 256 );
	if (mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, data_len, iv, data, result )) {
		return data_len;
	}
#endif
	return -1;
}

size_t aes_encrypt(unsigned char* key, const unsigned char* data, size_t data_len, unsigned char* result)
{
#ifndef __MINGW32__
	unsigned char iv[16];
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	mbedtls_aes_setkey_enc( &aes, key, 256 );
	if (mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, data_len, iv, data, result )) {
		return data_len;
	}
#endif
	return -1;
}

struct tlv_encryption_ctx* create_tlv_context(unsigned int enc_flag)
{
	struct tlv_encryption_ctx *ctx = malloc(sizeof(struct tlv_encryption_ctx));
	ctx->flag = enc_flag; // when consuming the context test initialization?

#ifndef __MINGW32__
	switch (enc_flag) {
		case ENC_AES256: {
			mbedtls_ctr_drbg_context ctr_drbg;
			mbedtls_entropy_context entropy;
			char *pers = "zrgrecergre zrggyr frrq"; // 'meterpreter mettle seed' rot13

			mbedtls_entropy_init(&entropy);
			mbedtls_ctr_drbg_init(&ctr_drbg);
			if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									  (unsigned char *) pers, strlen(pers))) {
				unsigned char *aes_key = malloc(sizeof(unsigned char) * AES_KEY_LEN);
				if (mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, AES_KEY_LEN)) {
					ctx->key = aes_key;
					ctx->key_len = AES_KEY_LEN;
					ctx->iv = (unsigned char *) AES_IV;
					ctx->iv_len = strlen(AES_IV);
					break;
				}
			}
		}
		case ENC_NONE:
			ctx->key = NULL;
			ctx->key_len = 0;
			ctx->iv = NULL;
			ctx->iv_len = 0;
	}
	return ctx;
#else
	ctx->key = NULL;
	ctx->key_len = 0;
	ctx->iv = NULL;
	ctx->iv_len = 0;

	return ctx;
#endif
}

void free_tlv_encryption_ctx(struct tlv_encryption_ctx *ctx)
{
	if (ctx->key_len != 0)
		free(ctx->key);
	if (ctx->iv_len != 0)
		free(ctx->iv);
	return free(ctx);
}

size_t decrypt_tlv(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result)
{
	/**
	 * TODO: consider taking result_len as a parameter for bounds check inside this method
	 * may also be valuable for malloc result buffer here
	 **/
	size_t length = 0;
	switch (ctx->flag) {
		case ENC_AES256:
			if ((length = aes_decrypt(ctx->key, data, data_len, result)) > 0) {
				return length;
			}
		case ENC_NONE:
			result = malloc(data_len);
			memcpy(result, data, data_len);
			return data_len;
		default:
			return -1;

	}
}

size_t encrypt_tlv(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result)
{
	/**
	 * TODO: consider taking result_len as a parameter for bounds check inside this method
	 * may also be valuable for malloc result buffer here
	 **/
	size_t length = 0;
	switch (ctx->flag) {
		case ENC_AES256:
			if ((length = aes_encrypt(ctx->key, data, data_len, result)) > 0) {
				return length;
			}
			// TODO: if failed should this return -1?
			return -1;
		case ENC_NONE:
			memcpy(result, data, data_len);
			return data_len;
		default:
			return -1;
	}
}

size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, const unsigned char* data, size_t data_len, unsigned char* result)
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
		// malloc result on the heap? or are we avoiding allocating memory to free later?
		return olen;
	}
#endif
	return -1;
}
