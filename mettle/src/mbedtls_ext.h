#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy_poll.h"


int mbedtls_entropy_remove_source(mbedtls_entropy_context *ctx, mbedtls_entropy_f_source_ptr f_source);
int mbedtls_mtwister_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen);