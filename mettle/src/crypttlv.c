#include "crypttlv.h"

size_t aes_decrypt(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result)
{
#ifndef __MINGW32__
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	mbedtls_aes_setkey_dec( &aes, ctx->key, 256 );
	size_t enc_len = data_len - AES_IV_LEN;
	unsigned char iv[AES_IV_LEN];
	const unsigned char *enc_data = data + AES_IV_LEN;
	memcpy(iv, data, AES_IV_LEN);
	if (!mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, enc_len, iv, enc_data, result)) {
		if(!ctx->iv) {
			ctx->iv = calloc(AES_IV_LEN, 1);
		}
		memcpy(ctx->iv, iv, AES_IV_LEN);
		return enc_len;
	}
#endif
	return 0;
}

size_t aes_encrypt(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result)
{
#ifndef __MINGW32__
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);

	size_t copy_len = data_len;
	if (!(copy_len % 16))
	mbedtls_aes_setkey_enc( &aes, ctx->key, 256 );
	if (!mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, copy_len, ctx->iv, data, result)) {
		return data_len;
	}
#endif
	return 0;
}

struct tlv_encryption_ctx* create_tlv_context(unsigned int enc_flag)
{
	struct tlv_encryption_ctx *ctx = malloc(sizeof(struct tlv_encryption_ctx));
	ctx->flag = enc_flag;

#ifndef __MINGW32__
	switch (enc_flag) {
		case ENC_AES256: {
			mbedtls_ctr_drbg_context ctr_drbg;
			mbedtls_entropy_context entropy;
			char *pers = "zrgrecergre zrggyr frrq"; // 'meterpreter mettle seed' rot13

			mbedtls_entropy_init(&entropy);
			mbedtls_ctr_drbg_init(&ctr_drbg);
			if (!(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									  (unsigned char *) pers, strlen(pers)))) {
				unsigned char *aes_key = calloc(sizeof(unsigned char) * AES_KEY_LEN, 1);
				if (!(mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, AES_KEY_LEN))) {
					ctx->key = aes_key;
					ctx->iv = NULL;
					ctx->initialized = false;
					mbedtls_ctr_drbg_free(&ctr_drbg);
					mbedtls_entropy_free(&entropy);
					break;
				}
			}
			mbedtls_ctr_drbg_free(&ctr_drbg);
			mbedtls_entropy_free(&entropy);
		}
		case ENC_NONE:
			ctx->key = NULL;
			ctx->iv = NULL;
			ctx->initialized = false;
	}
	return ctx;
#else
	ctx->key = NULL;
	ctx->iv = NULL;

	return ctx;
#endif
}

void free_tlv_encryption_ctx(struct tlv_encryption_ctx *ctx)
{
	if (ctx->key != NULL)
		free(ctx->key);
	if (ctx->iv != NULL)
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
			if ((length = aes_decrypt(ctx, data, data_len, result)) > 0) {
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
			if ((length = aes_encrypt(ctx, data, data_len, result)) > 0) {
				return length;
			}
		case ENC_NONE:
			memcpy(result, data, data_len);
			return data_len;
		default:
			return -1;
	}
}

size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, const unsigned char* data, size_t data_len, unsigned char* result)
{
	size_t olen = 0;
#ifndef __MINGW32__
	mbedtls_pk_context pk;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	char *pers = "zrgrecergre zrggyr frrq"; // 'meterpreter mettle seed' rot13

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (pkey_len > 0) {
		mbedtls_pk_init(&pk);
	}
	if (!(mbedtls_pk_parse_public_key(&pk, pkey, pkey_len))) {
		if (!(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
								  (unsigned char *) pers, strlen(pers)))) {
			unsigned char buf[MBEDTLS_MPI_MAX_SIZE] = { '\0' };

			if (!(mbedtls_pk_encrypt(&pk, data, data_len,
									buf, &olen, sizeof(buf),
									mbedtls_ctr_drbg_random, &ctr_drbg))) {
				memcpy(result, buf, olen);
			}
		}
	}
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#endif
	return olen;
}
