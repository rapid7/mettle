#include "crypttlv.h"
#include <unistd.h>
#include <string.h>
#include "log.h"

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

struct tlv_encryption_ctx* create_tlv_encryption_context(unsigned int enc_flag)
{
	struct tlv_encryption_ctx *ctx = malloc(sizeof(struct tlv_encryption_ctx));
	ctx->flag = enc_flag;
	ctx->is_weak_key = false;
#ifndef __MINGW32__
	switch (enc_flag) {
		case ENC_AES256: {
			mbedtls_ctr_drbg_context ctr_drbg;
			mbedtls_entropy_context entropy;
			int error_code = 0;
			mbedtls_entropy_init(&entropy);
			mbedtls_ctr_drbg_init(&ctr_drbg);

			error_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
			if (error_code != 0) {
				log_debug("mbedtls_ctr_drbg_seed: %d", error_code);
				log_debug("Removing: mbedtls_platform_entropy_poll");
				mbedtls_entropy_remove_source(&entropy, mbedtls_platform_entropy_poll);
				log_debug("Adding: mbedtls_mtwister_entropy_poll");
				mbedtls_entropy_add_source(&entropy, 
					mbedtls_mtwister_entropy_poll, 
					NULL, 
					MBEDTLS_ENTROPY_MIN_PLATFORM, 
					MBEDTLS_ENTROPY_SOURCE_STRONG);
				error_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
				log_debug("mbedtls_ctr_drbg_seed: %d", error_code);
				if(error_code == 0) { ctx->is_weak_key = true; };
			}

			if(error_code == 0) {
				unsigned char *aes_key = calloc(sizeof(unsigned char) * AES_KEY_LEN, 1);
				if(aes_key != NULL) {
					if (!(mbedtls_ctr_drbg_random(&ctr_drbg, aes_key, AES_KEY_LEN))) {
						ctx->key = aes_key;
						ctx->iv = NULL;
						ctx->initialized = false;
						mbedtls_ctr_drbg_free(&ctr_drbg);
						mbedtls_entropy_free(&entropy);
						break;
					}
				}
				if(aes_key != NULL) free(aes_key);
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
	free(ctx);
}

void * decrypt_tlv(struct tlv_encryption_ctx* ctx, void *p, size_t buf_len)
{
	size_t tlv_len = tlv_packet_len(p);
	if (tlv_len > buf_len)
		return NULL;
	tlv_len -= TLV_MIN_LEN;
	void *result = calloc(tlv_len, 1);
	if (ctx && result) {
		switch (ctx->flag) {
			case ENC_AES256:
				if (aes_decrypt(ctx, p + sizeof(struct tlv_header), tlv_len, result) > 0)
					break;
			case ENC_NONE:
			default:
				memcpy(result, p, tlv_len);
		}
	}
	return result;
}

void * encrypt_tlv(struct tlv_encryption_ctx* ctx, void *p, size_t buf_len)
{
	void *out_buf = NULL;
	void *tlv_buf = tlv_packet_data(p);
	size_t tlv_len = tlv_packet_len(p);
	if (tlv_len > buf_len)
		return NULL;
	size_t value_len = tlv_len - sizeof(struct tlv_header);
	if (ctx) {
		switch (ctx->flag) {
			case ENC_AES256: {
				size_t enc_size = ((value_len / AES_IV_LEN) + 1) * AES_IV_LEN;
				size_t pad_len = enc_size - value_len;
				size_t out_size = enc_size + AES_IV_LEN + TLV_PREPEND_LEN + TLV_MIN_LEN;
				out_buf = calloc(out_size, 1);
				if (out_buf) {
					size_t length = 0;
					struct tlv_xor_header *hdr = out_buf;
					memcpy(&hdr->tlv, tlv_buf, tlv_len);
					unsigned char *tlv_data = out_buf + sizeof(struct tlv_xor_header);
					memset(tlv_data + value_len, pad_len, pad_len);
					if (ctx->initialized) {
						hdr->encryption_flags = htonl(ctx->flag);
						unsigned char iv[AES_IV_LEN];
						memcpy(iv, ctx->iv, AES_IV_LEN); // grab iv before enc manipulates it.
						unsigned char *result = calloc(enc_size, 1);
						if (result) {
							if ((length = aes_encrypt(ctx, tlv_data, enc_size, result)) > 0) {
								memcpy(tlv_data, iv, AES_IV_LEN);
								memcpy(tlv_data + AES_IV_LEN, result, length);
								tlv_len = length + AES_IV_LEN + TLV_MIN_LEN;
								hdr->tlv.len = htonl(tlv_len);
							}
							free(result);
							break;
						}
					} else {
						ctx->initialized = true;
					}
				}
			}
			case ENC_NONE:
			default:
				out_buf = calloc(tlv_len + TLV_PREPEND_LEN, 1);
				if (out_buf) {
					struct tlv_xor_header *hdr = out_buf;
					memcpy(&hdr->tlv, tlv_buf, tlv_len);
				}
		}
	}
	return out_buf;
}

size_t rsa_encrypt_pkcs(unsigned char* pkey, size_t pkey_len, struct tlv_encryption_ctx* ctx, unsigned char* result)
{
	size_t olen = 0;
#ifndef __MINGW32__
	size_t data_len = 0;
	switch (ctx->flag)
	{
		case ENC_AES256:
			data_len = AES_KEY_LEN;
			break;
		default:
			break;
	}
	
	uint8_t *data = (uint8_t *)malloc(data_len + 1);
	if (data == NULL) return 0;

	memcpy(data, ctx->key, data_len);
	data[data_len++] = ctx->is_weak_key;
	int error_code = 0;
	mbedtls_pk_context pk;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if (pkey_len > 0) {
		mbedtls_pk_init(&pk);
	}
	if (!(mbedtls_pk_parse_public_key(&pk, pkey, pkey_len))) {
		error_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
		if (error_code != 0) {
			mbedtls_entropy_remove_source(&entropy, mbedtls_platform_entropy_poll);
			mbedtls_entropy_add_source(&entropy, 
				mbedtls_mtwister_entropy_poll, 
				NULL, 
				MBEDTLS_ENTROPY_MIN_PLATFORM, 
				MBEDTLS_ENTROPY_SOURCE_STRONG);
			error_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
		}
		if (error_code == 0) {
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
	free(data);
#endif
	return olen;
}
