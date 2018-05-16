#include "crypttlv.h"
#include "log.h"

size_t aes_decrypt(struct tlv_encryption_ctx* ctx, const unsigned char* data, size_t data_len, unsigned char* result)
{
#ifndef __MINGW32__
	mbedtls_aes_context aes;
	mbedtls_aes_init(&aes);
	log_info("aes_decrypt entered");
	mbedtls_aes_setkey_dec( &aes, ctx->key, 256 );
	log_info("aes_decrypt key set");
	size_t enc_len = data_len - AES_IV_LEN;
	unsigned char iv[AES_IV_LEN];
	const unsigned char *enc_data = data + AES_IV_LEN;
	memcpy(iv, data, AES_IV_LEN);
	log_info("aes_decrypt IV: 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X",
			 iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
			 iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]);
	if (!mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_DECRYPT, enc_len, iv, enc_data, result)) {
		log_info("aes_decrypt succeeded");
		size_t blocks = enc_len / 16;
		for (int i = 0 ; i < blocks; i++)
		{
			log_info("aes_decrypt row %d: 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X",
				i, result[i + 0], result[i + 1], result[i + 2], result[i + 3], result[i + 4], result[i + 5], result[i + 6], result[i + 7],
				result[i + 8], result[i + 9], result[i + 10], result[i + 11], result[i + 12], result[i + 13], result[i + 14], result[i + 15]);
		}
		if(!ctx->iv) {
			ctx->iv = calloc(AES_IV_LEN, 1);
		}
		memcpy(ctx->iv, iv, AES_IV_LEN);
		return enc_len;
	}
	log_info("aes_decrypt failed");
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
		log_info("aes_encrypt: data to encrypt is missing padding");
	log_info("aes_encrypt IV: 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X",
			 ctx->iv[0], ctx->iv[1], ctx->iv[2], ctx->iv[3], ctx->iv[4], ctx->iv[5], ctx->iv[6], ctx->iv[7],
			 ctx->iv[8], ctx->iv[9], ctx->iv[10], ctx->iv[11], ctx->iv[12], ctx->iv[13], ctx->iv[14], ctx->iv[15]);
	mbedtls_aes_setkey_enc( &aes, ctx->key, 256 );
	if (!mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, copy_len, ctx->iv, data, result)) {
		log_info("aes_encrypt new IV: 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X",
				 ctx->iv[0], ctx->iv[1], ctx->iv[2], ctx->iv[3], ctx->iv[4], ctx->iv[5], ctx->iv[6], ctx->iv[7],
				 ctx->iv[8], ctx->iv[9], ctx->iv[10], ctx->iv[11], ctx->iv[12], ctx->iv[13], ctx->iv[14], ctx->iv[15]);
		log_info("aes_encrypt first row: 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X",
				 result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
				 result[8], result[9], result[10], result[11], result[12], result[13], result[14], result[15]);
		log_info("aes_encrypt last row: 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X",
				 result[data_len-16], result[data_len-15], result[data_len-14], result[data_len-13], result[data_len-12], result[data_len-11], result[data_len-10], result[data_len-9],
				 result[data_len-8], result[data_len-7], result[data_len-6], result[data_len-5], result[data_len-4], result[data_len-3], result[data_len-2], result[data_len-1]);

		return data_len;
	}
#endif
	return 0;
}

struct tlv_encryption_ctx* create_tlv_context(unsigned int enc_flag)
{
	struct tlv_encryption_ctx *ctx = malloc(sizeof(struct tlv_encryption_ctx));
	ctx->flag = enc_flag; // when consuming the context test initialization?
	log_info("create_tlv_context entered");

#ifndef __MINGW32__
	switch (enc_flag) {
		case ENC_AES256: {
			mbedtls_ctr_drbg_context ctr_drbg;
			mbedtls_entropy_context entropy;
			char *pers = "zrgrecergre zrggyr frrq"; // 'meterpreter mettle seed' rot13
			log_info("create_tlv_context creating ENC_AES256 key");

			mbedtls_entropy_init(&entropy);
			mbedtls_ctr_drbg_init(&ctr_drbg);
			if (!(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									  (unsigned char *) pers, strlen(pers)))) {
				unsigned char *aes_key = calloc(sizeof(unsigned char) * AES_KEY_LEN, 1);
				log_info("create_tlv_context generated random seed");
				if (!(mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, AES_KEY_LEN))) {
					ctx->key = aes_key;
					ctx->iv = NULL;
					ctx->initialized = false;
					log_info("create_tlv_context obtained random key");
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
	log_info("decrypt_tlv entered");
	switch (ctx->flag) {
		case ENC_AES256:
			log_info("decrypt_tlv processing as ENC_AES256");
			if ((length = aes_decrypt(ctx, data, data_len, result)) > 0) {
				log_info("decrypt_tlv length after processing of %lu", (long unsigned int)length);
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
	log_info("encrypt_tlv entered");
	switch (ctx->flag) {
		case ENC_AES256:
			log_info("encrypt_tlv processing encrypted data %lu", (long unsigned int)data_len);
			if ((length = aes_encrypt(ctx, data, data_len, result)) > 0) {
				log_info("encrypt_tlv returning encrypted data");
				return length;
			}
		case ENC_NONE:
			memcpy(result, data, data_len);
			log_info("encrypt_tlv returning original data");
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
	log_info("rsa_encrypt_pkcs entered");

	if (pkey_len > 0) {
		mbedtls_pk_init(&pk);
	}
	if (mbedtls_pk_parse_public_key(&pk, pkey, pkey_len) != 0)
	{
		log_info("rsa_encrypt_pkcs failed to parse public key");
	} else {
		log_info("rsa_encrypt_pkcs parsed public key");

		if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
								  (unsigned char *) pers, strlen(pers))) {
			log_info("rsa_encrypt_pkcs failed to seed random generator");
		} else {
			log_info("rsa_encrypt_pkcs seeded random generator");
			unsigned char buf[MBEDTLS_MPI_MAX_SIZE] = { '\0' };

			if ((mbedtls_pk_encrypt(&pk, data, data_len,
									buf, &olen, sizeof(buf),
									mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
				log_info("rsa_encrypt_pkcs failed to encrypt aes key");
			} else {
				memcpy(result, buf, olen);
				log_info("rsa_encrypt_pkcs encrypted aes key size %lu became %lu", (long unsigned int) data_len,
						 (long unsigned int) olen);
			}
		}
	}
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
#endif
	return olen;
}
